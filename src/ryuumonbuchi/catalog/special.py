"""Special server, extension, and batch tool specs."""

from __future__ import annotations

from .schema import ToolSpec

TOOL_SPECS: tuple[ToolSpec, ...] = (
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
    ),
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
    ),
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
    ),
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
    ),
)
