"""Structural contract for the modular `ryuumonbuchi.backend.GhidraBackend` façade."""

from __future__ import annotations

import inspect

import pytest

import ryuumonbuchi.backend.state as backend_state
from ryuumonbuchi import backend as facade
from ryuumonbuchi.backend import GhidraBackend
from ryuumonbuchi.catalog import TOOL_SPECS

EXPECTED_MRO: list[tuple[str, str]] = [
    ("ryuumonbuchi.backend.core", "_BackendCore"),
    ("ryuumonbuchi.backend.records", "_RecordMixin"),
    ("ryuumonbuchi.backend.resolvers", "_ResolverMixin"),
    ("ryuumonbuchi.backend.program", "_ProgramMixin"),
    ("ryuumonbuchi.backend.analysis", "_AnalysisMixin"),
    ("ryuumonbuchi.backend.listing", "_ListingMixin"),
    ("ryuumonbuchi.backend.search", "_SearchMixin"),
    ("ryuumonbuchi.backend.symbols", "_SymbolMixin"),
    ("ryuumonbuchi.backend.references", "_ReferenceMixin"),
    ("ryuumonbuchi.backend.functions", "_FunctionMixin"),
    ("ryuumonbuchi.backend.types", "_TypeMixin"),
]


def test_facade_mixin_mro_is_exact_and_ordered() -> None:
    actual = [(b.__module__, b.__name__) for b in GhidraBackend.__mro__[1:-1]]
    assert actual == EXPECTED_MRO


def test_facade_defines_no_operation_methods() -> None:
    leftover = [
        name
        for name, value in GhidraBackend.__dict__.items()
        if callable(value) or inspect.isfunction(value)
    ]
    assert leftover == []


@pytest.mark.parametrize(
    "name",
    [
        "BackendConfig",
        "GhidraBackendError",
        "SessionRecord",
        "TaskRecord",
        "MAX_MEMORY_READ_BYTES",
        "DEFAULT_ANALYSIS_TIMEOUT",
    ],
)
def test_facade_re_exports_state_definitions(name: str) -> None:
    assert getattr(facade, name) is getattr(backend_state, name)


def test_all_catalog_methods_resolve_on_facade() -> None:
    for spec in TOOL_SPECS:
        if spec.backend_method is None:
            continue
        method = getattr(GhidraBackend, spec.backend_method, None)
        assert method is not None, f"missing backend method {spec.backend_method}"
        assert not method.__name__.startswith("__getattr__")


def test_backend_parameter_surface_matches_schema() -> None:
    for spec in TOOL_SPECS:
        if spec.backend_method is None:
            continue
        method = getattr(GhidraBackend, spec.backend_method)
        signature = inspect.signature(method)
        param_names = {name for name in signature.parameters if name != "self"}
        schema_props = set(spec.input_schema.get("properties", {}))
        assert param_names == schema_props, (
            f"{spec.name}: backend params {sorted(param_names)} != "
            f"schema props {sorted(schema_props)}"
        )
        required = {
            name
            for name, param in signature.parameters.items()
            if name != "self" and param.default is inspect.Parameter.empty
        }
        schema_required = set(spec.input_schema.get("required", []))
        assert required == schema_required, (
            f"{spec.name}: backend required {sorted(required)} != "
            f"schema required {sorted(schema_required)}"
        )
