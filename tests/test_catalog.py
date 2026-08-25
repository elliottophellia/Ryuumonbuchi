"""Catalog consistency: 216 tools, exact grouped set, no legacy names, schema invariants."""

from __future__ import annotations

import pytest

from ryuumonbuchi.catalog import (
    ADDRESS_PARAM_NAMES,
    TOOL_BY_NAME,
    TOOL_SPECS,
    assert_catalog_consistency,
    get_tool,
)

EXPECTED_GROUPS: dict[str, set[str]] = {
    "analysis": {
        "analysis.analyzers.list",
        "analysis.analyzers.set",
        "analysis.clear_cache",
        "analysis.options.get",
        "analysis.options.list",
        "analysis.options.set",
        "analysis.status",
        "analysis.update",
        "analysis.update_and_wait",
    },
    "bookmark": {"bookmark.add", "bookmark.clear", "bookmark.list", "bookmark.remove"},
    "class": {"class.create"},
    "comment": {"comment.get", "comment.get_all", "comment.list", "comment.set"},
    "context": {"context.get", "context.ranges", "context.set"},
    "decomp": {
        "decomp.ast",
        "decomp.function",
        "decomp.global.rename",
        "decomp.global.retype",
        "decomp.high_function.summary",
        "decomp.override.get",
        "decomp.override.set",
        "decomp.tokens",
        "decomp.trace_type.backward",
        "decomp.trace_type.forward",
        "decomp.writeback.locals",
        "decomp.writeback.params",
    },
    "equate": {"equate.clear_range", "equate.create", "equate.delete", "equate.list"},
    "external": {
        "external.entrypoint.add",
        "external.entrypoint.list",
        "external.entrypoint.remove",
        "external.function.create",
        "external.exports.list",
        "external.imports.list",
        "external.library.create",
        "external.library.list",
        "external.library.set_path",
        "external.location.create",
        "external.location.get",
    },
    "function": {
        "function.at",
        "function.batch.run",
        "function.body.set",
        "function.by_name",
        "function.callees",
        "function.callers",
        "function.calling_convention.set",
        "function.calling_conventions.list",
        "function.create",
        "function.delete",
        "function.flags.set",
        "function.list",
        "function.rename",
        "function.report",
        "function.return_type.set",
        "function.signature.get",
        "function.signature.set",
        "function.thunk.set",
        "function.variables",
    },
    "ghidra": {"ghidra.call", "ghidra.eval", "ghidra.info", "ghidra.script"},
    "graph": {"graph.basic_blocks", "graph.call_paths", "graph.cfg.edges"},
    "layout": {
        "layout.enum.create",
        "layout.enum.member.add",
        "layout.enum.member.remove",
        "layout.inspect.components",
        "layout.struct.bitfield.add",
        "layout.struct.create",
        "layout.struct.field.add",
        "layout.struct.field.clear",
        "layout.struct.field.comment.set",
        "layout.struct.field.rename",
        "layout.struct.field.replace",
        "layout.struct.fill_from_decompiler",
        "layout.struct.get",
        "layout.struct.resize",
        "layout.union.create",
        "layout.union.member.add",
        "layout.union.member.remove",
    },
    "listing": {
        "listing.clear",
        "listing.code_unit.after",
        "listing.code_unit.at",
        "listing.code_unit.before",
        "listing.code_unit.containing",
        "listing.code_units.list",
        "listing.data.at",
        "listing.data.clear",
        "listing.data.create",
        "listing.data.list",
        "listing.disassemble.function",
        "listing.disassemble.range",
        "listing.disassemble.seed",
    },
    "memory": {
        "memory.block.create",
        "memory.block.remove",
        "memory.blocks.list",
        "memory.read",
        "memory.write",
    },
    "metadata": {"metadata.query", "metadata.store"},
    "namespace": {"namespace.create"},
    "parameter": {"parameter.add", "parameter.move", "parameter.remove", "parameter.replace"},
    "patch": {"patch.assemble", "patch.branch_invert", "patch.nop"},
    "pcode": {"pcode.block", "pcode.function", "pcode.op.at", "pcode.varnode_uses"},
    "program": {
        "program.close",
        "program.export_binary",
        "program.export_packed",
        "program.image_base.set",
        "program.list_open",
        "program.mode.get",
        "program.mode.set",
        "program.open",
        "program.open_bytes",
        "program.report",
        "program.save",
        "program.save_as",
        "program.summary",
    },
    "project": {
        "project.export",
        "project.file.delete",
        "project.file.info",
        "project.files.list",
        "project.folders.list",
        "project.program.open",
        "project.program.open_existing",
        "project.search.programs",
    },
    "reference": {
        "reference.association.remove",
        "reference.association.set",
        "reference.clear_from",
        "reference.clear_to",
        "reference.create.external",
        "reference.create.memory",
        "reference.create.register",
        "reference.create.stack",
        "reference.delete",
        "reference.from",
        "reference.primary.set",
        "reference.to",
    },
    "relocation": {"relocation.add", "relocation.list"},
    "search": {
        "search.bytes",
        "search.constants",
        "search.defined_strings",
        "search.instructions",
        "search.pcode",
        "search.resolve",
        "search.text",
    },
    "source": {
        "source.file.add",
        "source.file.list",
        "source.file.remove",
        "source.map.add",
        "source.map.list",
        "source.map.remove",
    },
    "stackframe": {
        "stackframe.variable.clear",
        "stackframe.variable.create",
        "stackframe.variables",
    },
    "symbol": {
        "symbol.by_name",
        "symbol.create",
        "symbol.delete",
        "symbol.list",
        "symbol.namespace.move",
        "symbol.primary.set",
        "symbol.rename",
    },
    "tag": {"tag.add", "tag.list", "tag.remove", "tag.stats"},
    "task": {"task.analysis_update", "task.cancel", "task.result", "task.status"},
    "transaction": {
        "transaction.begin",
        "transaction.commit",
        "transaction.redo",
        "transaction.revert",
        "transaction.status",
        "transaction.undo",
    },
    "type": {
        "type.apply_at",
        "type.archives.list",
        "type.category.create",
        "type.category.list",
        "type.define_c",
        "type.delete",
        "type.get",
        "type.get_by_id",
        "type.list",
        "type.parse_c",
        "type.rename",
        "type.source_archives.list",
    },
    "variable": {
        "variable.comment.set",
        "variable.local.create",
        "variable.local.remove",
        "variable.rename",
        "variable.retype",
    },
}

EXPECTED_SERVER_TOOLS = {"health.ping", "mcp.response_format"}
EXPECTED_EXTENSION_TOOLS = {"headless.run", "operation.batch"}

BATCH_EXCLUSIONS = {
    "health.ping",
    "mcp.response_format",
    "ghidra.call",
    "ghidra.eval",
    "ghidra.info",
    "ghidra.script",
    "headless.run",
    "operation.batch",
    "program.open",
    "program.open_bytes",
    "program.close",
    "program.save",
    "program.save_as",
    "program.export_binary",
    "program.export_packed",
    "project.export",
    "project.program.open",
    "project.program.open_existing",
    "project.file.delete",
    "task.analysis_update",
    "task.status",
    "task.result",
    "task.cancel",
    "transaction.begin",
    "transaction.commit",
    "transaction.redo",
    "transaction.revert",
    "transaction.status",
    "transaction.undo",
    "program.list_open",
}


def test_exact_tool_count() -> None:
    assert len(TOOL_SPECS) == 216


def test_unique_names() -> None:
    names = [spec.name for spec in TOOL_SPECS]
    assert len(names) == len(set(names))


def test_no_underscore_legacy_names() -> None:
    """No tool name should be the old single-underscore style without a dot."""
    for spec in TOOL_SPECS:
        assert "." in spec.name, f"non-dotted tool name: {spec.name}"
        prefix, _, _leaf = spec.name.rpartition(".")
        assert prefix, f"tool name has no category prefix: {spec.name}"


def test_exact_grouped_set() -> None:
    all_expected: set[str] = set()
    for group_names in EXPECTED_GROUPS.values():
        all_expected |= group_names
    all_expected |= EXPECTED_SERVER_TOOLS
    all_expected |= EXPECTED_EXTENSION_TOOLS
    actual = {spec.name for spec in TOOL_SPECS}
    missing = all_expected - actual
    extra = actual - all_expected
    assert not missing, f"missing tools: {sorted(missing)}"
    assert not extra, f"unexpected tools: {sorted(extra)}"


def test_group_sizes() -> None:
    for prefix, expected_names in EXPECTED_GROUPS.items():
        actual = {spec.name for spec in TOOL_SPECS if spec.name.startswith(prefix + ".")}
        assert actual == expected_names, f"group {prefix}: mismatch — {actual ^ expected_names}"


def test_backend_method_count() -> None:
    backend_methods = {spec.backend_method for spec in TOOL_SPECS if spec.backend_method}
    assert len(backend_methods) == 212


def test_every_backend_method_has_spec() -> None:
    method_specs = [spec for spec in TOOL_SPECS if spec.backend_method]
    method_names = [spec.backend_method for spec in method_specs]
    assert len(method_names) == len(set(method_names)), "duplicate backend methods"


def test_array_schemas_have_items() -> None:
    for spec in TOOL_SPECS:
        for prop_name, prop_schema in spec.input_schema.get("properties", {}).items():
            if prop_schema.get("type") == "array":
                assert "items" in prop_schema, f"{spec.name}.{prop_name}: array without items"


def test_roots_are_objects_with_additional_properties_false() -> None:
    for spec in TOOL_SPECS:
        schema = spec.input_schema
        assert schema.get("type") == "object", f"{spec.name}: root not object"
        assert schema.get("additionalProperties") is False, (
            f"{spec.name}: additionalProperties not false"
        )
        assert "properties" in schema, f"{spec.name}: no properties"
        assert "required" in schema, f"{spec.name}: no required"


def test_address_unions_present() -> None:
    """Address params must accept int or string."""
    address_params_found = False
    for spec in TOOL_SPECS:
        for prop_name, prop_schema in spec.input_schema.get("properties", {}).items():
            if prop_name in ADDRESS_PARAM_NAMES:
                address_params_found = True
                # Must be a union of integer and string
                if "oneOf" in prop_schema:
                    types = {opt.get("type") for opt in prop_schema["oneOf"]}
                    assert "integer" in types and "string" in types, (
                        f"{spec.name}.{prop_name}: address union missing int/str"
                    )
    assert address_params_found, "no address params found in any schema"


def test_get_tool() -> None:
    assert get_tool("health.ping") is not None
    assert get_tool("function.list") is not None
    assert get_tool("headless.run") is not None
    assert get_tool("operation.batch") is not None
    assert get_tool("nonexistent") is None


def test_tool_by_name_matches_specs() -> None:
    assert len(TOOL_BY_NAME) == len(TOOL_SPECS)
    for spec in TOOL_SPECS:
        assert TOOL_BY_NAME[spec.name] is spec


def test_health_ping_is_jvm_lazy() -> None:
    spec = get_tool("health.ping")
    assert spec is not None
    assert spec.backend_method is None
    assert spec.read_only is True


def test_mcp_response_format() -> None:
    spec = get_tool("mcp.response_format")
    assert spec is not None
    assert spec.backend_method is None
    assert spec.read_only is True


def test_headless_run_classification() -> None:
    spec = get_tool("headless.run")
    assert spec is not None
    assert spec.backend_method is None
    assert spec.read_only is False
    assert spec.destructive is True
    assert spec.open_world is True
    assert spec.batch_allowed is False
    props = spec.input_schema["properties"]
    assert "arguments" in props
    assert props["arguments"]["type"] == "array"
    assert "items" in props["arguments"]


def test_operation_batch_classification() -> None:
    spec = get_tool("operation.batch")
    assert spec is not None
    assert spec.backend_method is None
    assert spec.read_only is False
    assert spec.destructive is True
    assert spec.batch_allowed is False
    props = spec.input_schema["properties"]
    assert "session_id" in props
    assert "operations" in props
    assert props["operations"]["type"] == "array"
    assert props["operations"].get("minItems") == 1
    assert props["operations"].get("maxItems") == 32


def test_batch_exclusions_exhaustive() -> None:
    non_batchable = {spec.name for spec in TOOL_SPECS if not spec.batch_allowed}
    assert non_batchable == BATCH_EXCLUSIONS, (
        f"batch exclusion mismatch: {BATCH_EXCLUSIONS ^ non_batchable}"
    )


def test_all_batchable_tools_have_session_id() -> None:
    for spec in TOOL_SPECS:
        if spec.batch_allowed:
            props = spec.input_schema.get("properties", {})
            assert "session_id" in props, f"batchable tool {spec.name} lacks session_id"


def test_assert_catalog_consistency_runs() -> None:
    assert_catalog_consistency()


def test_descriptions_non_empty() -> None:
    for spec in TOOL_SPECS:
        assert spec.description, f"{spec.name}: empty description"
        assert len(spec.description) > 10, f"{spec.name}: too-short description"


def test_read_only_tools_are_not_destructive() -> None:
    for spec in TOOL_SPECS:
        if spec.read_only:
            assert not spec.destructive, f"{spec.name}: read_only but destructive"


@pytest.mark.parametrize("spec", TOOL_SPECS, ids=lambda s: s.name)
def test_spec_has_all_fields(spec: object) -> None:
    from ryuumonbuchi.catalog import ToolSpec

    assert isinstance(spec, ToolSpec)
    assert isinstance(spec.name, str)
    assert isinstance(spec.backend_method, str | type(None))
    assert isinstance(spec.description, str)
    assert isinstance(spec.input_schema, dict)
    assert isinstance(spec.read_only, bool)
    assert isinstance(spec.destructive, bool)
    assert isinstance(spec.open_world, bool)
    assert isinstance(spec.batch_allowed, bool)
