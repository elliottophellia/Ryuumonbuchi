"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from .backend_analysis import _AnalysisMixin
from .backend_core import _BackendCore
from .backend_functions import _FunctionMixin
from .backend_listing import _ListingMixin
from .backend_program import _ProgramMixin
from .backend_records import _RecordMixin
from .backend_references import _ReferenceMixin
from .backend_resolvers import _ResolverMixin
from .backend_search import _SearchMixin
from .backend_state import (
    DEFAULT_ANALYSIS_TIMEOUT,
    MAX_MEMORY_READ_BYTES,
    BackendConfig,
    GhidraBackendError,
    SessionRecord,
    TaskRecord,
)
from .backend_symbols import _SymbolMixin
from .backend_types import _TypeMixin

__all__ = [
    "DEFAULT_ANALYSIS_TIMEOUT",
    "MAX_MEMORY_READ_BYTES",
    "BackendConfig",
    "GhidraBackendError",
    "SessionRecord",
    "TaskRecord",
]


class GhidraBackend(
    _BackendCore,
    _RecordMixin,
    _ResolverMixin,
    _ProgramMixin,
    _AnalysisMixin,
    _ListingMixin,
    _SearchMixin,
    _SymbolMixin,
    _ReferenceMixin,
    _FunctionMixin,
    _TypeMixin,
):
    """High-level Ghidra operations exposed to MCP tools."""
