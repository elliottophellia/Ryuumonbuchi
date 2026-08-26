"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from .analysis import _AnalysisMixin
from .core import _BackendCore
from .functions import _FunctionMixin
from .listing import _ListingMixin
from .program import _ProgramMixin
from .records import _RecordMixin
from .references import _ReferenceMixin
from .resolvers import _ResolverMixin
from .search import _SearchMixin
from .state import (
    DEFAULT_ANALYSIS_TIMEOUT,
    MAX_MEMORY_READ_BYTES,
    BackendConfig,
    GhidraBackendError,
    SessionRecord,
    TaskRecord,
)
from .symbols import _SymbolMixin
from .types import _TypeMixin

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
