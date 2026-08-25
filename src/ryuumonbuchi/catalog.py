"""Authoritative 216-tool registry: names, schemas, annotations, batch eligibility."""

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


def _build_specs() -> tuple[ToolSpec, ...]:
    specs: list[ToolSpec] = []
    # Server tools
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
    # Backend tools (210 from reference + 2 Ryuumonbuchi extensions)
    specs.append(
        ToolSpec(
            name="ghidra.info",
            backend_method="ghidra_info",
            description=(
                "Return runtime information about Ghidra, PyGhidra, and the serverenvironment."
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
            name="program.open",
            backend_method="session_open",
            description="Open a binary file for analysis and return a new session.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "update_analysis": {"type": "boolean"},
                    "read_only": {"type": "boolean"},
                    "project_location": {"type": "string"},
                    "project_name": {"type": "string"},
                    "program_name": {"type": "string"},
                    "language": {"type": "string"},
                    "compiler": {"type": "string"},
                    "loader": {"type": "string"},
                },
                "required": ["path"],
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
            name="program.open_bytes",
            backend_method="session_open_bytes",
            description="Open a binary from base64-encoded bytes and return a new session.",
            input_schema={
                "type": "object",
                "properties": {
                    "data_base64": {"type": "string"},
                    "filename": {"type": "string"},
                    "update_analysis": {"type": "boolean"},
                    "read_only": {"type": "boolean"},
                    "project_location": {"type": "string"},
                    "project_name": {"type": "string"},
                    "program_name": {"type": "string"},
                    "language": {"type": "string"},
                    "compiler": {"type": "string"},
                    "loader": {"type": "string"},
                },
                "required": ["data_base64"],
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
            name="project.program.open_existing",
            backend_method="session_open_existing",
            description=(
                "Open a program from a named existing Ghidra project and return a newsession."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "project_location": {"type": "string"},
                    "project_name": {"type": "string"},
                    "program_path": {"type": "string"},
                    "folder_path": {"type": "string"},
                    "program_name": {"type": "string"},
                    "read_only": {"type": "boolean"},
                    "update_analysis": {"type": "boolean"},
                },
                "required": ["project_location", "project_name"],
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
            name="program.close",
            backend_method="session_close",
            description="Close an open program session and release its associated resources.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
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
            name="program.list_open",
            backend_method="session_list",
            description="List all program sessions currently held open by the server.",
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
            name="program.mode.get",
            backend_method="session_mode",
            description="Return whether a session is currently read-only or read-write.",
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
            name="program.mode.set",
            backend_method="session_set_mode",
            description="Switch a session between read-only and read-write mode.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "read_only": {"type": "boolean"},
                    "deterministic": {"type": "boolean"},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="analysis.status",
            backend_method="analysis_status",
            description="Return the current auto-analysis status for the session.",
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
            name="analysis.update",
            backend_method="analysis_update",
            description="Start auto-analysis in the background and return immediately.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
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
            name="analysis.update_and_wait",
            backend_method="analysis_update_and_wait",
            description="Run auto-analysis and wait until it completes.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
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
            name="analysis.options.list",
            backend_method="analysis_options_list",
            description="List available analysis options together with their current values.",
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
            name="analysis.options.get",
            backend_method="analysis_options_get",
            description="Return the current value of a specific analysis option.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "name": {"type": "string"}},
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
            name="analysis.options.set",
            backend_method="analysis_options_set",
            description="Update the value of an analysis option for the current session.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "value": {},
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
            name="program.summary",
            backend_method="binary_summary",
            description=(
                "Return core program metadata such as architecture, memory layout, andentry point."
            ),
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
            name="symbol.list",
            backend_method="binary_symbols",
            description="List symbols with filtering and pagination support.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "include_dynamic": {"type": "boolean"},
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
            name="search.defined_strings",
            backend_method="binary_strings",
            description="List defined strings discovered in the program.",
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
            name="external.imports.list",
            backend_method="binary_imports",
            description="List symbols imported by the program.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="external.exports.list",
            backend_method="binary_exports",
            description="List symbols exported by the program.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="memory.blocks.list",
            backend_method="binary_memory_blocks",
            description="List memory blocks together with addresses, permissions, and sizes.",
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
            name="listing.data.list",
            backend_method="binary_data",
            description=(
                "List defined data items in the program with range and paginationcontrols."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="listing.disassemble.function",
            backend_method="disasm_function",
            description="Disassemble all instructions that belong to a function body.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
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
            name="listing.disassemble.range",
            backend_method="disasm_range",
            description="Disassemble instructions across a selected address range.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "start", "length"],
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
            name="decomp.function",
            backend_method="decomp_function",
            description="Decompile a function and return recovered C source code.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "timeout_secs": {"type": "integer"},
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
            name="pcode.function",
            backend_method="pcode_function",
            description="Return per-instruction p-code for a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
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
            name="pcode.op.at",
            backend_method="pcode_op_at",
            description="Return the p-code ops generated by the instruction at an address.",
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
            name="reference.to",
            backend_method="xref_to",
            description="List cross-references that target an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
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
            name="reference.from",
            backend_method="xref_from",
            description="List cross-references that originate from an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
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
            name="comment.get",
            backend_method="annotation_comment_get",
            description="Return one comment type from a specific address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment_type": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "scope": {"type": "string"},
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
            name="comment.set",
            backend_method="annotation_comment_set",
            description="Set or clear a comment of a selected type at an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "comment": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment_type": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "scope": {"type": "string"},
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
            name="symbol.rename",
            backend_method="annotation_symbol_rename",
            description="Rename an existing symbol.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "new_name": {"type": "string"},
                    "old_name": {"type": "string"},
                },
                "required": ["session_id", "address", "new_name"],
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
            name="symbol.create",
            backend_method="annotation_symbol_create",
            description="Create a new symbol or label at an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "make_primary": {"type": "boolean"},
                },
                "required": ["session_id", "address", "name"],
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
            name="symbol.delete",
            backend_method="annotation_symbol_delete",
            description="Delete a symbol at an address, optionally by name.",
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
            name="memory.read",
            backend_method="memory_read",
            description="Read raw bytes directly from program memory.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "address", "length"],
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
            name="memory.write",
            backend_method="memory_write",
            description="Write raw bytes directly into program memory.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_base64": {"type": "string"},
                    "data_hex": {"type": "string"},
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
            name="listing.data.at",
            backend_method="data_typed_at",
            description="Return the defined data item at a specific address.",
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
            name="listing.data.create",
            backend_method="data_create",
            description="Create a data definition of a chosen type at an address.",
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
            name="listing.data.clear",
            backend_method="data_clear",
            description="Clear one or more data definitions starting at an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
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
            name="symbol.by_name",
            backend_method="symbol_by_name",
            description="Look up a symbol by name and return its details.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "exact": {"type": "boolean"},
                    "limit": {"type": "integer"},
                    "include_dynamic": {"type": "boolean"},
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
            name="search.resolve",
            backend_method="address_resolve",
            description="Resolve a symbol name or expression into an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "query": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "query"],
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
            name="search.text",
            backend_method="search_text",
            description="Search for text across defined strings and raw memory matches.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "text": {"type": "string"},
                    "case_sensitive": {"type": "boolean"},
                    "defined_strings_only": {"type": "boolean"},
                    "encoding": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "text"],
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
            name="search.bytes",
            backend_method="search_bytes",
            description="Search program memory for an exact byte pattern.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "pattern_base64": {"type": "string"},
                    "pattern_hex": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
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
            name="search.constants",
            backend_method="search_constants",
            description="Search instructions for scalar constant operands that match a value.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "value"],
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
            name="search.instructions",
            backend_method="search_instructions",
            description="Search instructions by mnemonic or rendered instruction text.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "query": {"type": "string"},
                    "case_sensitive": {"type": "boolean"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "query"],
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
            name="search.pcode",
            backend_method="search_pcode",
            description="Search p-code operations by mnemonic or rendered op text.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "query": {"type": "string"},
                    "case_sensitive": {"type": "boolean"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "query"],
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
            name="graph.basic_blocks",
            backend_method="function_basic_blocks",
            description="List the basic blocks that make up a function.",
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
            name="graph.cfg.edges",
            backend_method="cfg_edges",
            description="List control-flow edges between the basic blocks of a function.",
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
            name="graph.call_paths",
            backend_method="callgraph_paths",
            description="Find call graph paths between two functions up to a chosen depth.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "source_function": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "target_function": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "max_depth": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "required": ["session_id", "source_function", "target_function"],
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
            name="patch.assemble",
            backend_method="patch_assemble",
            description="Assemble instruction text at an address and write the resulting bytes.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "assembly": {"type": "string"},
                },
                "required": ["session_id", "address", "assembly"],
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
            name="patch.nop",
            backend_method="patch_nop",
            description="Replace instructions in a range with NOP bytes.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "count": {"type": "integer"},
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
            name="patch.branch_invert",
            backend_method="patch_branch_invert",
            description="Invert a conditional branch instruction in place.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="program.save",
            backend_method="session_save",
            description="Save the current program state back into the project.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="program.save_as",
            backend_method="session_save_as",
            description="Save the current program under a new project path or name.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "program_name": {"type": "string"},
                    "folder_path": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["session_id", "program_name"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="project.export",
            backend_method="session_export_project",
            description="Export the current Ghidra project artifacts to a destination directory.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "destination": {"type": "string"}},
                "required": ["session_id", "destination"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="program.export_binary",
            backend_method="session_export_binary",
            description=(
                "Export the program to disk as either the original-file format or rawbytes."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "format": {"type": "string"},
                },
                "required": ["session_id", "path"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="bookmark.add",
            backend_method="bookmark_add",
            description="Add a bookmark at an address with a type, category, and comment.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "category": {"type": "string"},
                    "comment": {"type": "string"},
                    "bookmark_type": {"type": "string"},
                },
                "required": ["session_id", "address", "category", "comment"],
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
            name="bookmark.list",
            backend_method="bookmark_list",
            description="List bookmarks, optionally scoped to an address or bookmark type.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "bookmark_type": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="tag.add",
            backend_method="tag_add",
            description="Create or reuse a function tag and attach it to a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "comment": {"type": "string"},
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
            name="tag.list",
            backend_method="tag_list",
            description="List tags for one function or across the whole program.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="metadata.store",
            backend_method="metadata_store",
            description="Store a JSON-serializable metadata value under a program-scoped key.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {},
                },
                "required": ["session_id", "key", "value"],
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
            name="metadata.query",
            backend_method="metadata_query",
            description=(
                "Read metadata entries stored by this server, optionally filtered by keyor prefix."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                    "prefix": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="analysis.analyzers.list",
            backend_method="analysis_analyzers_list",
            description=(
                "List boolean analyzers available for the current program and show"
                "whether each one is enabled."
            ),
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
            name="analysis.analyzers.set",
            backend_method="analysis_analyzers_set",
            description="Enable or disable a specific boolean analyzer for the current program.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "enabled": {"type": "boolean"},
                },
                "required": ["session_id", "name", "enabled"],
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
            name="analysis.clear_cache",
            backend_method="analysis_clear_cache",
            description=(
                "Clear cached decompiler state for the current session so later requests"
                "rebuild it cleanly."
            ),
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=False,
            open_world=False,
            batch_allowed=True,
        )
    )
    specs.append(
        ToolSpec(
            name="memory.block.create",
            backend_method="memory_block_create",
            description=(
                "Create a memory block with permissions, initialization, and an optionalcomment."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                    "initialized": {"type": "boolean"},
                    "fill": {"type": "integer"},
                    "read": {"type": "boolean"},
                    "write": {"type": "boolean"},
                    "execute": {"type": "boolean"},
                    "comment": {"type": "string"},
                },
                "required": ["session_id", "name", "address", "length"],
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
            name="memory.block.remove",
            backend_method="memory_block_remove",
            description="Remove an existing memory block from the program.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="external.library.list",
            backend_method="external_library_list",
            description="List external libraries known to the program.",
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
            name="external.location.get",
            backend_method="external_location_get",
            description="Return details for a specific external location.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="decomp.tokens",
            backend_method="decomp_tokens",
            description="Decompile a function and return tokenized Clang markup for the output.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "timeout_secs": {"type": "integer"},
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
            name="decomp.ast",
            backend_method="decomp_ast",
            description="Decompile a function and return the Clang markup tree for the result.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "timeout_secs": {"type": "integer"},
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
            name="pcode.block",
            backend_method="pcode_block",
            description="Return per-instruction p-code for the basic block containing an address.",
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
            name="pcode.varnode_uses",
            backend_method="pcode_varnode_uses",
            description="Find p-code reads and writes that match a selected varnode.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "varnode": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "space": {"type": "string"},
                    "size": {"type": "integer"},
                    "timeout_secs": {"type": "integer"},
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
            name="program.report",
            backend_method="report_program_summary",
            description=(
                "Return a compact program report with counts plus sample functions,"
                "strings, imports, and memory blocks."
            ),
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
            name="program.image_base.set",
            backend_method="binary_rebase",
            description=(
                "Change the program image base. The rebase is always applied to the open"
                "program in memory; commit controls whether the change is recorded in the"
                "undo stack."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "image_base": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "commit": {"type": "boolean"},
                },
                "required": ["session_id", "image_base"],
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
            name="transaction.begin",
            backend_method="undo_begin",
            description="Begin an explicit undo transaction for grouped changes.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "description": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="transaction.commit",
            backend_method="undo_commit",
            description="Commit the active transaction so its changes become undoable.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="transaction.revert",
            backend_method="undo_revert",
            description="Roll back the active transaction without committing it.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="transaction.undo",
            backend_method="undo_undo",
            description="Undo the most recently committed change.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="transaction.redo",
            backend_method="undo_redo",
            description="Reapply the most recently undone change.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="transaction.status",
            backend_method="undo_status",
            description="Return undo, redo, and active-transaction status for the session.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
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
            name="task.analysis_update",
            backend_method="task_analysis_update",
            description="Start auto-analysis as a tracked background task and return a task ID.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="task.status",
            backend_method="task_status",
            description=(
                "Return status, timing, and cancellation details for an asynchronoustask."
            ),
            input_schema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"],
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
            name="task.result",
            backend_method="task_result",
            description="Return the terminal result or error payload for a completed task.",
            input_schema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"],
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
            name="task.cancel",
            backend_method="task_cancel",
            description="Request cancellation for a running or queued asynchronous task.",
            input_schema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"],
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
            name="ghidra.call",
            backend_method="call_api",
            description=(
                "Invoke Ghidra or Java APIs directly through a generic bridge. Raw access"
                "to a read-only session requires write=true and transitions it to"
                "writable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "args": {"type": "array", "items": {}},
                    "kwargs": {"type": "object"},
                    "session_id": {"type": "string"},
                    "write": {"type": "boolean"},
                },
                "required": ["target"],
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
            name="ghidra.eval",
            backend_method="eval_code",
            description=(
                "Evaluate Python code inside the live Ghidra runtime context. Raw access"
                "to a read-only session requires write=true and transitions it to"
                "writable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "session_id": {"type": "string"},
                    "write": {"type": "boolean"},
                },
                "required": ["code"],
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
            name="ghidra.script",
            backend_method="run_script",
            description=(
                "Run a Ghidra script against an open program session. Raw access to a"
                "read-only session requires write=true and transitions it to writable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "session_id": {"type": "string"},
                    "script_args": {"type": "array", "items": {"type": "string"}},
                    "write": {"type": "boolean"},
                },
                "required": ["path"],
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
            name="project.folders.list",
            backend_method="project_folders_list",
            description="List project folders, optionally walking the tree recursively.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "folder_path": {"type": "string"},
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
            name="project.files.list",
            backend_method="project_files_list",
            description=(
                "List project files with folder, content-type, query, and paginationfilters."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "folder_path": {"type": "string"},
                    "recursive": {"type": "boolean"},
                    "content_type": {"type": "string"},
                    "query": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="project.file.info",
            backend_method="project_file_info",
            description="Return metadata and state flags for a specific project file.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "path": {"type": "string"}},
                "required": ["session_id", "path"],
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
            name="project.program.open",
            backend_method="project_program_open",
            description=(
                "Open a program already stored in the current project and return a newsession."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "read_only": {"type": "boolean"},
                    "update_analysis": {"type": "boolean"},
                },
                "required": ["session_id", "path"],
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
            name="project.search.programs",
            backend_method="project_search_programs",
            description="Search program files in the project by name or path.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "query": {"type": "string"},
                    "content_type": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="listing.code_units.list",
            backend_method="listing_code_units_list",
            description="List code units in a range with pagination and direction controls.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                    "forward": {"type": "boolean"},
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
            name="listing.code_unit.at",
            backend_method="listing_code_unit_at",
            description="Return the code unit that starts exactly at a given address.",
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
            name="listing.code_unit.before",
            backend_method="listing_code_unit_before",
            description="Return the nearest code unit that precedes a given address.",
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
            name="listing.code_unit.after",
            backend_method="listing_code_unit_after",
            description="Return the nearest code unit that follows a given address.",
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
            name="listing.code_unit.containing",
            backend_method="listing_code_unit_containing",
            description="Return the code unit that contains a given address.",
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
            name="listing.clear",
            backend_method="listing_clear",
            description=(
                "Clear listing content over a range, including optional symbols,"
                "comments, references, functions, or context."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                    "clear_context": {"type": "boolean"},
                    "clear_symbols": {"type": "boolean"},
                    "clear_comments": {"type": "boolean"},
                    "clear_properties": {"type": "boolean"},
                    "clear_functions": {"type": "boolean"},
                    "clear_registers": {"type": "boolean"},
                    "clear_equates": {"type": "boolean"},
                    "clear_user_references": {"type": "boolean"},
                    "clear_analysis_references": {"type": "boolean"},
                    "clear_import_references": {"type": "boolean"},
                    "clear_default_references": {"type": "boolean"},
                    "clear_bookmarks": {"type": "boolean"},
                },
                "required": ["session_id", "start"],
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
            name="listing.disassemble.seed",
            backend_method="listing_disassemble_seed",
            description="Start disassembly from a seed address and follow discovered flows.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer"},
                    "clear_existing": {"type": "boolean"},
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
            name="context.get",
            backend_method="context_get",
            description="Return processor context register values at a specific address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "register": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "signed": {"type": "boolean"},
                },
                "required": ["session_id", "register", "address"],
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
            name="context.set",
            backend_method="context_set",
            description="Set processor context register values across an address range.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "register": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                    "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "clear": {"type": "boolean"},
                },
                "required": ["session_id", "register", "start"],
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
            name="context.ranges",
            backend_method="context_ranges",
            description="List address ranges where a processor context register value applies.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "register": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "register"],
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
            name="symbol.primary.set",
            backend_method="symbol_primary_set",
            description="Mark a selected symbol as the primary symbol at its address.",
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
            name="namespace.create",
            backend_method="namespace_create",
            description="Create a namespace under an optional parent namespace.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "parent": {"type": "string"},
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
            name="class.create",
            backend_method="class_create",
            description="Create a class namespace for recovered methods or fields.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "parent": {"type": "string"},
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
            name="symbol.namespace.move",
            backend_method="symbol_namespace_move",
            description="Move a symbol into a different namespace.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "namespace": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["session_id", "address", "namespace"],
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
            name="external.library.create",
            backend_method="external_library_create",
            description="Create a new external library record.",
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "name": {"type": "string"}},
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
            name="external.library.set_path",
            backend_method="external_library_set_path",
            description="Set or update the filesystem path associated with an external library.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "path": {"type": "string"},
                    "user_defined": {"type": "boolean"},
                },
                "required": ["session_id", "name", "path"],
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
            name="external.location.create",
            backend_method="external_location_create",
            description="Create an external location for a symbol within a library.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "library_name": {"type": "string"},
                    "label": {"type": "string"},
                    "external_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "library_name"],
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
            name="external.function.create",
            backend_method="external_function_create",
            description="Create an external function symbol under an external location.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "library_name": {"type": "string"},
                    "name": {"type": "string"},
                    "external_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "library_name", "name"],
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
            name="external.entrypoint.add",
            backend_method="external_entrypoint_add",
            description="Add an address to the program's external entry point set.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="external.entrypoint.remove",
            backend_method="external_entrypoint_remove",
            description="Remove an address from the external entry point set.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="external.entrypoint.list",
            backend_method="external_entrypoint_list",
            description="List addresses currently marked as external entry points.",
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
            name="reference.create.memory",
            backend_method="reference_create_memory",
            description="Create a memory reference between two program addresses.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "reference_type": {"type": "string"},
                    "operand_index": {"type": "integer"},
                    "source_type": {"type": "string"},
                },
                "required": ["session_id", "from_address", "to_address"],
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
            name="reference.create.stack",
            backend_method="reference_create_stack",
            description="Create a reference from an address to a stack location.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "stack_offset": {"type": "integer"},
                    "reference_type": {"type": "string"},
                    "operand_index": {"type": "integer"},
                    "source_type": {"type": "string"},
                },
                "required": ["session_id", "from_address", "stack_offset"],
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
            name="reference.create.register",
            backend_method="reference_create_register",
            description="Create a reference from an address to a register.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "register": {"type": "string"},
                    "reference_type": {"type": "string"},
                    "operand_index": {"type": "integer"},
                    "source_type": {"type": "string"},
                },
                "required": ["session_id", "from_address", "register"],
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
            name="reference.create.external",
            backend_method="reference_create_external",
            description="Create a reference from an address to an external location.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "library_name": {"type": "string"},
                    "label": {"type": "string"},
                    "external_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "reference_type": {"type": "string"},
                    "operand_index": {"type": "integer"},
                    "source_type": {"type": "string"},
                },
                "required": ["session_id", "from_address", "library_name"],
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
            name="reference.delete",
            backend_method="reference_delete",
            description=(
                "Delete a specific reference selected by source, destination, andoperand."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                },
                "required": ["session_id", "from_address"],
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
            name="reference.clear_from",
            backend_method="reference_clear_from",
            description="Remove references originating from one address or an address range.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "from_address"],
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
            name="reference.clear_to",
            backend_method="reference_clear_to",
            description="Remove all references that target a specific address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "to_address"],
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
            name="reference.primary.set",
            backend_method="reference_primary_set",
            description="Mark a specific reference as the primary one for its operand.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                },
                "required": ["session_id", "from_address", "to_address"],
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
            name="reference.association.set",
            backend_method="reference_association_set",
            description="Associate a specific reference with a symbol.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                    "symbol_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "symbol_name": {"type": "string"},
                },
                "required": ["session_id", "from_address", "to_address", "symbol_address"],
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
            name="reference.association.remove",
            backend_method="reference_association_remove",
            description="Remove the symbol association attached to a specific reference.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "from_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "to_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                },
                "required": ["session_id", "from_address", "to_address"],
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
            name="equate.create",
            backend_method="equate_create",
            description="Create an equate and attach it to an operand at an address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                },
                "required": ["session_id", "address", "name", "value"],
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
            name="equate.list",
            backend_method="equate_list",
            description="List equates together with values and attached references.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="equate.delete",
            backend_method="equate_delete",
            description=(
                "Delete an equate entirely, or remove one of its references beforedeletion."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "operand_index": {"type": "integer"},
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
            name="equate.clear_range",
            backend_method="equate_clear_range",
            description=(
                "Remove equate references across an address range and delete emptyequates."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "start"],
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
            name="comment.get_all",
            backend_method="comment_get_all",
            description=(
                "Return all available comment types at an address, with optional functioncomments."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "include_function": {"type": "boolean"},
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
            name="comment.list",
            backend_method="comment_list",
            description="List comments matching range, type, text, and pagination filters.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment_type": {"type": "string"},
                    "query": {"type": "string"},
                    "case_sensitive": {"type": "boolean"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
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
            name="bookmark.remove",
            backend_method="bookmark_remove",
            description="Remove bookmarks at an address, optionally filtered by type or category.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "bookmark_type": {"type": "string"},
                    "category": {"type": "string"},
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
            name="bookmark.clear",
            backend_method="bookmark_clear",
            description=(
                "Remove bookmarks in an address range, optionally filtered by bookmarktype."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                    "bookmark_type": {"type": "string"},
                },
                "required": ["session_id", "start"],
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
            name="tag.remove",
            backend_method="tag_remove",
            description="Remove a function tag from a function.",
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
            name="tag.stats",
            backend_method="tag_stats",
            description="Summarize function tags and the number of functions using each one.",
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
            name="source.file.list",
            backend_method="source_file_list",
            description="List all source files currently registered with the program.",
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
            name="source.file.add",
            backend_method="source_file_add",
            description="Register a source file record with the program's source file manager.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "id_type": {"type": "string"},
                    "identifier_hex": {"type": "string"},
                },
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
            name="source.file.remove",
            backend_method="source_file_remove",
            description="Remove a source file record by path.",
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
            name="source.map.list",
            backend_method="source_map_list",
            description="List source mapping entries by address, source file, or line filters.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "path": {"type": "string"},
                    "min_line": {"type": "integer"},
                    "max_line": {"type": "integer"},
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
            name="source.map.add",
            backend_method="source_map_add",
            description="Add a source mapping entry from a source line to an address range.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "base_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer"},
                },
                "required": ["session_id", "path", "line_number", "base_address", "length"],
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
            name="source.map.remove",
            backend_method="source_map_remove",
            description="Remove a specific source mapping entry by file, line, and base address.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "base_address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "path", "line_number", "base_address"],
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
            name="relocation.list",
            backend_method="relocation_list",
            description="List relocation entries, optionally limited to an address range.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
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
            name="relocation.add",
            backend_method="relocation_add",
            description=(
                "Add a relocation entry at an address with type, status, values, and"
                "symbol metadata."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "status": {"type": "string"},
                    "type": {"type": "integer"},
                    "values": {"type": "array", "items": {"type": "integer"}},
                    "byte_length": {"type": "integer"},
                    "symbol_name": {"type": "string"},
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
            name="decomp.high_function.summary",
            backend_method="decomp_high_function_summary",
            description=(
                "Summarize the high-function view, including local symbols, globals,"
                "blocks, and jump tables."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "timeout_secs": {"type": "integer"},
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
            name="decomp.writeback.params",
            backend_method="decomp_writeback_params",
            description=(
                "Commit decompiler-recovered parameter information back into the programdatabase."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "use_data_types": {"type": "boolean"},
                    "commit_return": {"type": "boolean"},
                    "timeout_secs": {"type": "integer"},
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
            name="decomp.writeback.locals",
            backend_method="decomp_writeback_locals",
            description="Commit decompiler-recovered local names back into the program database.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "timeout_secs": {"type": "integer"},
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
            name="decomp.override.get",
            backend_method="decomp_override_get",
            description="Return the decompiler call override, if any, for a specific callsite.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "callsite": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                "required": ["session_id", "function_start", "callsite"],
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
            name="decomp.override.set",
            backend_method="decomp_override_set",
            description=(
                "Set or replace the decompiler call override signature for a specificcallsite."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "callsite": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "signature": {"type": "string"},
                },
                "required": ["session_id", "function_start", "callsite", "signature"],
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
            name="decomp.trace_type.forward",
            backend_method="decomp_trace_type_forward",
            description="Trace type propagation forward from a selected decompiler symbol.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                    "timeout_secs": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "name"],
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
            name="decomp.trace_type.backward",
            backend_method="decomp_trace_type_backward",
            description="Trace type propagation backward from a selected decompiler symbol.",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "ordinal": {"type": "integer"},
                    "storage": {"type": "string"},
                    "timeout_secs": {"type": "integer"},
                },
                "required": ["session_id", "function_start", "name"],
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
            name="decomp.global.rename",
            backend_method="decomp_global_rename",
            description=(
                "Rename a global symbol selected through decompiler high-symbolinformation."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "new_name": {"type": "string"},
                    "storage": {"type": "string"},
                    "timeout_secs": {"type": "integer"},
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
            name="decomp.global.retype",
            backend_method="decomp_global_retype",
            description=(
                "Retype a global symbol selected through decompiler high-symbolinformation."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "data_type": {"type": "string"},
                    "storage": {"type": "string"},
                    "timeout_secs": {"type": "integer"},
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
            name="program.export_packed",
            backend_method="program_export_packed",
            description="Export the program to disk as a lossless Ghidra packed file (GZF).",
            input_schema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "destination_path": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["session_id", "destination_path"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=False,
            open_world=False,
            batch_allowed=False,
        )
    )
    specs.append(
        ToolSpec(
            name="project.file.delete",
            backend_method="project_file_delete",
            description=(
                "Delete a project file by exact project path; rejects an open domainobject."
            ),
            input_schema={
                "type": "object",
                "properties": {"session_id": {"type": "string"}, "path": {"type": "string"}},
                "required": ["session_id", "path"],
                "additionalProperties": False,
            },
            read_only=False,
            destructive=True,
            open_world=False,
            batch_allowed=False,
        )
    )
    # Ryuumonbuchi native + batch tools
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
    return tuple(_apply_schema_bounds(specs))


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


def _apply_schema_bounds(specs: list[ToolSpec]) -> list[ToolSpec]:
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
