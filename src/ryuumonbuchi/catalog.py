"""Authoritative 216-tool registry: names, schemas, annotations, batch eligibility."""

from __future__ import annotations

from .catalog_analysis import TOOL_SPECS as _ANALYSIS_SPECS
from .catalog_listing import TOOL_SPECS as _LISTING_SPECS
from .catalog_order import order_specs as _order_specs
from .catalog_program import TOOL_SPECS as _PROGRAM_SPECS
from .catalog_references import TOOL_SPECS as _REFERENCES_SPECS
from .catalog_schema import (
    ADDRESS_PARAM_NAMES,
    ADDRESS_SCHEMA,
    ToolSpec,
)
from .catalog_schema import (
    apply_schema_bounds as _apply_schema_bounds,
)
from .catalog_search import TOOL_SPECS as _SEARCH_SPECS
from .catalog_symbols import TOOL_SPECS as _SYMBOLS_SPECS

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
    specs.append(
        ToolSpec(
            name="health.ping",
            backend_method=None,
            description="Confirm that the server is reachable and responding.",
            input_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="mcp.response_format",
            backend_method=None,
            description=(
                "Explain how MCP tool responses split full structured data and"
                "human-readable summary text."
            ),
            input_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="function.list",
            backend_method="binary_functions",
            description="List functions in the program with filtering and pagination support.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "query": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.at",
            backend_method="binary_get_function_at",
            description="Return the function that starts at, or contains, a specific address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "address"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.callers",
            backend_method="function_callers",
            description="List the functions that call a specific function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.callees",
            backend_method="function_callees",
            description="List the functions called by a specific function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.signature.get",
            backend_method="function_signature_get",
            description="Return the full signature of a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.signature.set",
            backend_method="function_signature_set",
            description="Apply a full C-style signature declaration to a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "signature": {"type": "string"},
                },
                "required": ["session_id", "function_start", "signature"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.variables",
            backend_method="function_variables",
            description="List parameters and local variables for a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.rename",
            backend_method="function_rename",
            description="Rename an existing function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.list",
            backend_method="type_list",
            description="List data types with filtering and pagination support.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "query": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.get",
            backend_method="type_get",
            description="Return details for a data type by name or full path.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.define_c",
            backend_method="type_define_c",
            description="Define a new data type from a C declaration.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "declaration": {"type": "string"},
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                },
                "required": ["session_id", "declaration"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.rename",
            backend_method="type_rename",
            description="Rename an existing data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "name": {"type": "string"},
                    "new_name": {"type": "string"},
                },
                "required": ["session_id", "new_name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.delete",
            backend_method="type_delete",
            description="Delete a data type by name or full path.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.by_name",
            backend_method="function_by_name",
            description="Look up a function by name and return its details.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "exact": {"type": "boolean"},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "name"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="variable.rename",
            backend_method="function_variable_rename",
            description="Rename a local variable or parameter.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "new_name": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "new_name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="variable.retype",
            backend_method="function_variable_retype",
            description="Change the data type of a local variable or parameter.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.return_type.set",
            backend_method="function_return_type_set",
            description="Set the return type of a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_type": {"type": "string"},
                },
                "required": ["session_id", "function_start", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.create",
            backend_method="function_create",
            description="Create a new function at a given address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "address"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.delete",
            backend_method="function_delete",
            description="Delete a function at a given address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.parse_c",
            backend_method="type_parse_c",
            description=(
                "Parse a C declaration and return the resulting type without necessarily"
                "committing it."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "declaration": {"type": "string"},
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                },
                "required": ["session_id", "declaration"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.apply_at",
            backend_method="type_apply_at",
            description="Apply a data type at an address in the listing.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_type": {"type": "string"},
                    "length": {"type": "integer"},
                    "clear_existing": {"type": "boolean"},
                },
                "required": ["session_id", "address", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.create",
            backend_method="struct_create",
            description="Create a structure data type in a chosen category.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.field.add",
            backend_method="struct_field_add",
            description="Add a field to a structure at a specific offset or append position.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "field_name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "offset": {"type": "integer"},
                    "length": {"type": "integer"},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.field.rename",
            backend_method="struct_field_rename",
            description="Rename a structure field.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "old_name": {"type": "string"},
                    "new_name": {"type": "string"},
                    "offset": {"type": "integer"},
                    "ordinal": {"type": "integer"},
                },
                "required": ["session_id", "new_name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.enum.create",
            backend_method="enum_create",
            description="Create an enum data type in a chosen category.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                    "size": {"type": "integer"},
                },
                "required": ["session_id", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.enum.member.add",
            backend_method="enum_member_add",
            description="Add a named value to an enum data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "enum_path": {"type": "string"},
                    "enum_name": {"type": "string"},
                    "name": {"type": "string"},
                    "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "name", "value"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.report",
            backend_method="report_function_summary",
            description=(
                "Return a richer function report with signature, variables, call graph"
                "edges, xrefs, and decompilation output."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.batch.run",
            backend_method="batch_run_on_functions",
            description="Run one supported action across a filtered batch of functions.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "action": {"type": "string"},
                    "query": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "timeout_secs": {"type": "integer"},
                },
                "required": ["session_id", "action"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.body.set",
            backend_method="function_body_set",
            description="Replace the body range of an existing function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "start"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.calling_conventions.list",
            backend_method="function_calling_conventions_list",
            description="List calling conventions available in the current program.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.calling_convention.set",
            backend_method="function_calling_convention_set",
            description="Set the calling convention used by a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.flags.set",
            backend_method="function_flags_set",
            description=(
                "Update function flags such as varargs, inline, noreturn, or customstorage."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "varargs": {"type": "boolean"},
                    "inline": {"type": "boolean"},
                    "noreturn": {"type": "boolean"},
                    "custom_storage": {"type": "boolean"},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="function.thunk.set",
            backend_method="function_thunk_set",
            description="Mark a function as a thunk to another function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "thunk_target": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start", "thunk_target"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="parameter.add",
            backend_method="parameter_add",
            description="Add a new parameter to a function with a chosen type and storage.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "stack_offset": {"type": "integer"},
                    "register": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="parameter.remove",
            backend_method="parameter_remove",
            description="Remove a parameter from a function by ordinal or name.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "ordinal": {"type": "integer"},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="parameter.move",
            backend_method="parameter_move",
            description="Reorder a parameter to a new ordinal within the signature.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "ordinal": {"type": "integer"},
                    "new_ordinal": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "ordinal", "new_ordinal"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="parameter.replace",
            backend_method="parameter_replace",
            description="Replace an existing parameter definition by ordinal or name.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "ordinal": {"type": "integer"},
                    "name": {"type": "string"},
                    "new_name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "stack_offset": {"type": "integer"},
                    "register": {"type": "string"},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="variable.local.create",
            backend_method="variable_local_create",
            description=(
                "Create a local variable with explicit type, storage, and optionalcomment."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "first_use_offset": {"type": "integer"},
                    "stack_offset": {"type": "integer"},
                    "register": {"type": "string"},
                    "storage_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="variable.local.remove",
            backend_method="variable_local_remove",
            description="Remove a local variable from a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "storage": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="variable.comment.set",
            backend_method="variable_comment_set",
            description="Set or clear the comment attached to a local variable or parameter.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "comment": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "comment"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="stackframe.variable.create",
            backend_method="stackframe_variable_create",
            description="Create a stack-frame variable at a specific stack offset.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "stack_offset": {"type": "integer"},
                    "data_type": {"type": "string"},
                },
                "required": ["session_id", "function_start", "name", "stack_offset", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="stackframe.variable.clear",
            backend_method="stackframe_variable_clear",
            description="Clear a stack-frame variable at a specific stack offset.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "stack_offset": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "stack_offset"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="stackframe.variables",
            backend_method="stackframe_variables",
            description="List stack-frame variables for a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.category.list",
            backend_method="type_category_list",
            description="List data type categories under a path, optionally recursively.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "recursive": {"type": "boolean"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.category.create",
            backend_method="type_category_create",
            description="Create a new data type category path.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "path": {"type": "string"}},
                "required": ["session_id", "path"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.archives.list",
            backend_method="type_archives_list",
            description="List the current program archive plus attached source archives.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.source_archives.list",
            backend_method="type_source_archives_list",
            description="List source archives referenced by the current data type manager.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="type.get_by_id",
            backend_method="type_get_by_id",
            description="Look up a data type by internal ID, universal ID, or source archive ID.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "data_type_id": {"type": "integer"},
                    "universal_id": {"type": "integer"},
                    "source_archive_id": {"type": "integer"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.get",
            backend_method="layout_struct_get",
            description="Return a structure definition together with its components.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.resize",
            backend_method="layout_struct_resize",
            description="Resize a structure to a specific total length.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "length"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.field.replace",
            backend_method="layout_struct_field_replace",
            description=(
                "Replace an existing structure field with a new type, size, name, orcomment."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "offset": {"type": "integer"},
                    "data_type": {"type": "string"},
                    "length": {"type": "integer"},
                    "field_name": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "offset", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.field.clear",
            backend_method="layout_struct_field_clear",
            description="Clear a field from a structure by offset, ordinal, or field name.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "offset": {"type": "integer"},
                },
                "required": ["session_id", "offset"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.field.comment.set",
            backend_method="layout_struct_field_comment_set",
            description="Set or clear the comment on a structure field.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "offset": {"type": "integer"},
                    "ordinal": {"type": "integer"},
                    "field_name": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "comment"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.bitfield.add",
            backend_method="layout_struct_bitfield_add",
            description="Insert a bitfield into a structure at a byte and bit offset.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "struct_path": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "byte_offset": {"type": "integer"},
                    "byte_width": {"type": "integer"},
                    "bit_offset": {"type": "integer"},
                    "data_type": {"type": "string"},
                    "bit_size": {"type": "integer"},
                    "field_name": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "required": [
                    "session_id",
                    "byte_offset",
                    "byte_width",
                    "bit_offset",
                    "data_type",
                    "bit_size",
                ],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.union.create",
            backend_method="layout_union_create",
            description="Create a union data type in a chosen category.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                },
                "required": ["session_id", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.union.member.add",
            backend_method="layout_union_member_add",
            description="Add a member to a union data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "union_path": {"type": "string"},
                    "union_name": {"type": "string"},
                    "field_name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "length": {"type": "integer"},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "data_type"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.union.member.remove",
            backend_method="layout_union_member_remove",
            description="Remove a member from a union data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "union_path": {"type": "string"},
                    "union_name": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "field_name": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.enum.member.remove",
            backend_method="layout_enum_member_remove",
            description="Remove a named member from an enum data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "enum_path": {"type": "string"},
                    "enum_name": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.inspect.components",
            backend_method="layout_inspect_components",
            description="Inspect the component layout of a composite data type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=True,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="layout.struct.fill_from_decompiler",
            backend_method="layout_struct_fill_from_decompiler",
            description=(
                "Build or extend a structure from decompiler-observed usage of avariable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                    "create_new_structure": {"type": "boolean"},
                    "create_class_if_needed": {"type": "boolean"},
                    "timeout_secs": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="headless.run",
            backend_method=None,
            description=(
                "Run the installed Ghidra analyzeHeadless launcher with exact argv. Full"
                "filesystem/process/network access enabled by default; runs in a child"
                "process group."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "arguments": {"type": "array", "items": {"type": "string"}, "maxItems": 1000},
                    "working_directory": {"type": ["string", "null"]},
                    "environment": {"type": "object", "additionalProperties": {"type": "string"}},
                    "stdin_text": {"type": ["string", "null"]},
                    "terminal": {"type": "boolean"},
                    "timeout_seconds": {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "maximum": 86400,
                    },
                },
                "required": ["arguments"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=True,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="operation.batch",
            backend_method=None,
            description=(
                "Execute 1-32 program-bound operations atomically in the persistent"
                "child. Read-only batches run without a transaction; mutating batches use"
                "one transaction with rollback on error."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "operations": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 32,
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string"},
                                "arguments": {"type": "object"},
                            },
                            "required": ["tool"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["session_id", "operations"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
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

    from .backend import GhidraBackend

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
