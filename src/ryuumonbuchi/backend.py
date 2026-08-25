"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from typing import Any

from .backend_analysis import _AnalysisMixin
from .backend_core import _BackendCore
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
):
    """High-level Ghidra operations exposed to MCP tools."""

    def binary_functions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        funcs = list(self._get_program(session_id).getFunctionManager().getFunctions(True))
        if query:
            needle = query.lower()
            funcs = [func for func in funcs if needle in func.getName().lower()]
        items = [self._function_record(func) for func in funcs[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(funcs),
            "count": len(items),
            "items": items,
        }

    def binary_get_function_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        return {"session_id": session_id, "function": self._function_record(function)}

    def function_callers(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callers = sorted(
            function.getCallingFunctions(self._pyghidra.task_monitor()), key=self._function_sort_key
        )
        items = [self._function_record(func) for func in callers]
        return {
            "session_id": session_id,
            "function_start": self._addr_str(function.getEntryPoint()),
            "count": len(items),
            "items": items,
        }

    def function_callees(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callees = sorted(
            function.getCalledFunctions(self._pyghidra.task_monitor()), key=self._function_sort_key
        )
        items = [self._function_record(func) for func in callees]
        return {
            "session_id": session_id,
            "function_start": self._addr_str(function.getEntryPoint()),
            "count": len(items),
            "items": items,
        }

    def function_signature_get(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "signature": function.getPrototypeString(False, True),
            "calling_convention": function.getCallingConventionName(),
            "signature_source": str(function.getSignatureSource()),
            "return_type": function.getReturnType().getPathName(),
            "parameters": [self._parameter_record(param) for param in function.getParameters()],
        }

    def function_signature_set(
        self, session_id: str, function_start: int | str, signature: str
    ) -> dict[str, Any]:
        if not signature:
            raise GhidraBackendError("signature is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.symbol import SourceType

            definition = CParserUtils.parseSignature(
                None, self._get_program(session_id), signature, False
            )
            if definition is None:
                raise GhidraBackendError("failed to parse function signature")
            cmd = ApplyFunctionSignatureCmd(
                function.getEntryPoint(), definition, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(self._get_program(session_id)):
                raise GhidraBackendError(
                    getattr(cmd, "getStatusMsg", lambda: None)()
                    or "failed to apply function signature"
                )

        self._with_write(session_id, f"Set function signature {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_variables(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "parameters": [self._parameter_record(param) for param in function.getParameters()],
            "locals": [self._variable_record(var) for var in function.getLocalVariables()],
        }

    def function_rename(
        self, session_id: str, function_start: int | str, name: str
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            function.setName(name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename function {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def type_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        types = sorted(self._get_all_data_types(session_id), key=lambda dt: dt.getPathName())
        if query:
            needle = query.lower()
            types = [dt for dt in types if needle in dt.getPathName().lower()]
        items = [self._data_type_record(dt) for dt in types[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(types),
            "count": len(items),
            "items": items,
        }

    def type_get(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def type_define_c(
        self,
        session_id: str,
        *,
        declaration: str,
        name: str | None = None,
        category: str = "/",
    ) -> dict[str, Any]:
        if not declaration:
            raise GhidraBackendError("declaration is required")
        resolved = None

        def mutate() -> None:
            nonlocal resolved
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                TypedefDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            normalized = declaration.strip().rstrip(";")
            if self._is_full_c_declaration(normalized):
                parsed = self._parse_c_declaration(session_id, normalized)
                chosen_name = name or parsed.getName()
                parsed.setNameAndCategory(
                    CategoryPath(self._normalize_category_path(category)), chosen_name
                )
                resolved = dtm.addDataType(parsed, DataTypeConflictHandler.DEFAULT_HANDLER)
                return
            if "(" in normalized and ")" in normalized:
                func_def = CParserUtils.parseSignature(
                    None, self._get_program(session_id), normalized, False
                )
                if func_def is None:
                    raise GhidraBackendError("failed to parse function declaration")
                resolved = dtm.addDataType(func_def, DataTypeConflictHandler.DEFAULT_HANDLER)
                return
            if not name:
                raise GhidraBackendError("name is required for non-function type definitions")
            base = self._parse_data_type(session_id, normalized)
            typedef = TypedefDataType(
                CategoryPath(self._normalize_category_path(category)), name, base, dtm
            )
            resolved = dtm.addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Define type {name or declaration}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(resolved)}

    def type_rename(
        self, session_id: str, *, path: str | None = None, name: str | None = None, new_name: str
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        data_type = self._resolve_data_type(session_id, path=path, name=name)

        def mutate() -> None:
            data_type.setName(new_name)

        self._with_write(session_id, f"Rename type {data_type.getName()}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def type_delete(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)

        def mutate() -> bool:
            return bool(self._get_program(session_id).getDataTypeManager().remove(data_type))

        deleted = self._with_write(session_id, f"Delete type {data_type.getName()}", mutate)
        return {
            "session_id": session_id,
            "deleted": deleted,
            "type": self._data_type_record(data_type),
        }

    def function_by_name(
        self,
        session_id: str,
        name: str,
        *,
        exact: bool = False,
        limit: int = 20,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        funcs = sorted(
            self._get_program(session_id).getFunctionManager().getFunctions(True),
            key=self._function_sort_key,
        )
        if exact:
            matched = [func for func in funcs if func.getName() == name]
        else:
            needle = name.lower()
            matched = [func for func in funcs if needle in func.getName().lower()]
        items = [self._function_record(func) for func in matched[:limit]]
        return {
            "session_id": session_id,
            "query": name,
            "exact": exact,
            "limit": limit,
            "total": len(matched),
            "count": len(items),
            "items": items,
        }

    def function_variable_rename(
        self,
        session_id: str,
        function_start: int | str,
        *,
        name: str,
        new_name: str,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if not new_name:
            raise GhidraBackendError("new_name is required")
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)

        def mutate() -> None:
            high_symbol = self._find_high_symbol(
                session_id,
                function,
                name=name,
                ordinal=ordinal,
                storage=storage,
            )
            if high_symbol is not None:
                self._update_high_symbol(
                    session_id,
                    function,
                    high_symbol,
                    name=new_name,
                    data_type=None,
                )
                return
            from ghidra.program.model.symbol import SourceType

            variable.setName(new_name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename variable {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def function_variable_retype(
        self,
        session_id: str,
        function_start: int | str,
        *,
        name: str,
        data_type: str,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if not data_type:
            raise GhidraBackendError("data_type is required")
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            high_symbol = self._find_high_symbol(
                session_id,
                function,
                name=name,
                ordinal=ordinal,
                storage=storage,
            )
            if high_symbol is not None:
                self._update_high_symbol(
                    session_id,
                    function,
                    high_symbol,
                    name=None,
                    data_type=parsed,
                )
                return
            from ghidra.program.model.symbol import SourceType

            variable.setDataType(parsed, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Retype variable {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def function_return_type_set(
        self,
        session_id: str,
        function_start: int | str,
        *,
        data_type: str,
    ) -> dict[str, Any]:
        if not data_type:
            raise GhidraBackendError("data_type is required")
        function = self._resolve_function(session_id, function_start)
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            function.setReturnType(parsed, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Set return type {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createFunction(addr, name)
            if created is None:
                created = self._get_program(session_id).getFunctionManager().getFunctionAt(addr)
            if created is None:
                raise GhidraBackendError(f"failed to create function at {self._addr_str(addr)}")

        self._with_write(session_id, f"Create function {name or self._addr_str(addr)}", mutate)
        return {"session_id": session_id, "function": self._function_record(created)}

    def function_delete(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        entry = function.getEntryPoint()
        deleted_name = function.getName()

        def mutate() -> None:
            self._get_record(session_id).flat_api.removeFunctionAt(entry)

        self._with_write(session_id, f"Delete function {deleted_name}", mutate)
        return {
            "session_id": session_id,
            "deleted": True,
            "entry_point": self._addr_str(entry),
            "name": deleted_name,
        }

    def type_parse_c(
        self,
        session_id: str,
        *,
        declaration: str,
        name: str | None = None,
        category: str = "/",
    ) -> dict[str, Any]:
        if not declaration:
            raise GhidraBackendError("declaration is required")
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError(
                "type.parse_c cannot run during an active transaction; commit or revert it first"
            )
        # Open a temporary transaction that is always rolled back: some Ghidra
        # parsers (including the full C parser used for composite/typedef
        # declarations) register types with the dtm while parsing, and we want
        # parse to be non-mutating.
        program = self._get_program(session_id)
        tx_id = int(program.startTransaction("Parse C type"))
        try:
            normalized = declaration.strip().rstrip(";")
            if self._is_full_c_declaration(normalized):
                parsed = self._parse_c_declaration(session_id, normalized)
                if name is not None or self._normalize_category_path(category) != "/":
                    from ghidra.program.model.data import CategoryPath

                    parsed.setNameAndCategory(
                        CategoryPath(self._normalize_category_path(category)),
                        name or parsed.getName(),
                    )
                return {
                    "session_id": session_id,
                    "kind": "composite" if "{" in normalized else "data_type",
                    "type": self._data_type_record(parsed),
                }
            if "(" in normalized and ")" in normalized:
                from ghidra.app.util.cparser.C import CParserUtils

                definition = CParserUtils.parseSignature(None, program, normalized, False)
                if definition is None:
                    raise GhidraBackendError("failed to parse function declaration")
                return {
                    "session_id": session_id,
                    "kind": "function_signature",
                    "signature": definition.getPrototypeString(False),
                    "type": self._data_type_record(definition),
                }
            parsed = self._parse_data_type(session_id, normalized)
            return {
                "session_id": session_id,
                "kind": "data_type",
                "type": self._data_type_record(parsed),
            }
        finally:
            program.endTransaction(tx_id, False)

    def type_apply_at(
        self,
        session_id: str,
        address: int | str,
        *,
        data_type: str,
        length: int | None = None,
        clear_existing: bool = True,
    ) -> dict[str, Any]:
        return self.data_create(
            session_id,
            address,
            data_type=data_type,
            length=length,
            clear_existing=clear_existing,
        )

    def struct_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
        length: int = 0,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if length < 0:
            raise GhidraBackendError("length must be >= 0")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                StructureDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            struct = StructureDataType(
                CategoryPath(self._normalize_category_path(category)), name, length, dtm
            )
            created = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Create struct {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def struct_field_add(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        field_name: str | None = None,
        data_type: str,
        offset: int | None = None,
        length: int | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not data_type:
            raise GhidraBackendError("data_type is required")
        struct = self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        if not hasattr(struct, "getComponents") or not hasattr(struct, "add"):
            raise GhidraBackendError("target type is not a structure")
        parsed = self._parse_data_type(session_id, data_type)
        field_length = length if length is not None else int(parsed.getLength())
        if field_length <= 0:
            field_length = 1

        def mutate() -> None:
            if offset is None:
                struct.add(parsed, field_length, field_name, comment)
            else:
                struct.insertAtOffset(offset, parsed, field_length, field_name, comment)

        self._with_write(session_id, f"Add struct field {field_name or data_type}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(struct)}

    def struct_field_rename(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        old_name: str | None = None,
        new_name: str,
        offset: int | None = None,
        ordinal: int | None = None,
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        struct = self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        if not hasattr(struct, "getComponents"):
            raise GhidraBackendError("target type is not a structure")
        component = None
        for candidate in struct.getComponents():
            if old_name is not None and candidate.getFieldName() == old_name:
                component = candidate
                break
            if offset is not None and int(candidate.getOffset()) == offset:
                component = candidate
                break
            if ordinal is not None and int(candidate.getOrdinal()) == ordinal:
                component = candidate
                break
        if component is None:
            raise GhidraBackendError("struct field not found")

        def mutate() -> None:
            component.setFieldName(new_name)

        self._with_write(session_id, f"Rename struct field {new_name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(struct)}

    def enum_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
        size: int = 4,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if size <= 0:
            raise GhidraBackendError("size must be > 0")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                EnumDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            enum_type = EnumDataType(
                CategoryPath(self._normalize_category_path(category)), name, size, dtm
            )
            created = dtm.addDataType(enum_type, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Create enum {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def enum_member_add(
        self,
        session_id: str,
        *,
        enum_path: str | None = None,
        enum_name: str | None = None,
        name: str,
        value: int | str,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        enum_type = self._resolve_data_type(session_id, path=enum_path, name=enum_name)
        if not hasattr(enum_type, "add") or not hasattr(enum_type, "getValues"):
            raise GhidraBackendError("target type is not an enum")
        numeric_value = int(value, 0) if isinstance(value, str) else int(value)

        def mutate() -> None:
            if comment is None:
                enum_type.add(name, numeric_value)
            else:
                enum_type.add(name, numeric_value, comment)

        self._with_write(session_id, f"Add enum member {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(enum_type)}

    def report_function_summary(
        self, session_id: str, *, function_start: int | str
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        signature = self.function_signature_get(session_id, function.getEntryPoint())
        variables = self.function_variables(session_id, function.getEntryPoint())
        callers = self.function_callers(session_id, function.getEntryPoint())
        callees = self.function_callees(session_id, function.getEntryPoint())
        decomp = self.decomp_function(session_id, function.getEntryPoint())
        xrefs = self.xref_to(session_id, function.getEntryPoint())
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "signature": signature,
            "variables": {
                "parameter_count": len(variables["parameters"]),
                "local_count": len(variables["locals"]),
                "parameters": variables["parameters"],
                "locals": variables["locals"],
            },
            "callers": callers["items"],
            "callees": callees["items"],
            "xref_count": xrefs["count"],
            "decompile_completed": decomp["decompile_completed"],
            "c": decomp.get("c"),
        }

    def batch_run_on_functions(
        self,
        session_id: str,
        *,
        action: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 50,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        if not action:
            raise GhidraBackendError("action is required")
        funcs = sorted(
            self._get_program(session_id).getFunctionManager().getFunctions(True),
            key=self._function_sort_key,
        )
        if query:
            needle = query.lower()
            funcs = [func for func in funcs if needle in func.getName().lower()]
        selected = funcs[offset : offset + limit]
        actions: dict[str, Callable[[Any], Any]] = {
            "decomp.function": lambda func: self.decomp_function(
                session_id, func.getEntryPoint(), timeout_secs=timeout_secs
            ),
            "disasm.function": lambda func: self.disasm_function(session_id, func.getEntryPoint()),
            "function.signature.get": lambda func: self.function_signature_get(
                session_id, func.getEntryPoint()
            ),
            "function.variables": lambda func: self.function_variables(
                session_id, func.getEntryPoint()
            ),
            "function.callers": lambda func: self.function_callers(
                session_id, func.getEntryPoint()
            ),
            "function.callees": lambda func: self.function_callees(
                session_id, func.getEntryPoint()
            ),
            "report.function_summary": lambda func: self.report_function_summary(
                session_id, function_start=func.getEntryPoint()
            ),
        }
        if action not in actions:
            raise GhidraBackendError(
                "unsupported action; use one of: " + ", ".join(sorted(actions))
            )
        items = [
            {
                "function": self._function_record(func),
                "result": actions[action](func),
            }
            for func in selected
        ]
        return {
            "session_id": session_id,
            "action": action,
            "offset": offset,
            "limit": limit,
            "total": len(funcs),
            "count": len(items),
            "items": items,
        }

    def function_body_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        _start_addr, _end_addr, address_set = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> None:
            function.setBody(address_set)

        self._with_write(session_id, f"Set body for {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def function_calling_conventions_list(self, session_id: str) -> dict[str, Any]:
        compiler_spec = self._get_program(session_id).getCompilerSpec()
        items = [str(name) for name in compiler_spec.getCallingConventions()]
        return {"session_id": session_id, "count": len(items), "items": sorted(items)}

    def function_calling_convention_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            function.setCallingConvention(name)

        self._with_write(session_id, f"Set calling convention {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_flags_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        varargs: bool | None = None,
        inline: bool | None = None,
        noreturn: bool | None = None,
        custom_storage: bool | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            if varargs is not None:
                function.setVarArgs(bool(varargs))
            if inline is not None:
                function.setInline(bool(inline))
            if noreturn is not None:
                function.setNoReturn(bool(noreturn))
            if custom_storage is not None:
                function.setCustomVariableStorage(bool(custom_storage))

        self._with_write(session_id, f"Set flags {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def function_thunk_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        thunk_target: int | str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        target = self._resolve_function(session_id, thunk_target)

        def mutate() -> None:
            function.setThunkedFunction(target)

        self._with_write(session_id, f"Set thunk {function.getName()}", mutate)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "target": self._function_record(target),
        }

    def parameter_add(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        ordinal: int | None = None,
        stack_offset: int | None = None,
        register: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        param = self._parameter_from_spec(
            session_id,
            name=name,
            data_type=data_type,
            stack_offset=stack_offset,
            register=register,
        )
        index = len(params) if ordinal is None else max(0, min(len(params), ordinal))
        params.insert(index, param)
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=name)
        del params[index]
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_move(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int,
        new_ordinal: int,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=None)
        param = params.pop(index)
        params.insert(max(0, min(len(params), new_ordinal)), param)
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_replace(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int | None = None,
        name: str | None = None,
        new_name: str | None = None,
        data_type: str | None = None,
        stack_offset: int | None = None,
        register: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=name)
        current = params[index]
        params[index] = self._parameter_from_spec(
            session_id,
            name=new_name or current.getName(),
            data_type=data_type or current.getDataType().getPathName(),
            stack_offset=stack_offset,
            register=register,
            fallback=current,
        )
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_local_create(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        first_use_offset: int = 0,
        stack_offset: int | None = None,
        register: str | None = None,
        storage_address: int | str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)
        local = None
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            nonlocal local
            import jpype
            from ghidra.program.model.address import Address
            from ghidra.program.model.listing import LocalVariableImpl
            from ghidra.program.model.symbol import SourceType

            program = self._get_program(session_id)
            if register is not None:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    self._resolve_register(session_id, register),
                    program,
                    SourceType.USER_DEFINED,
                )
            elif storage_address is not None:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    self._coerce_address(session_id, storage_address, "storage_address"),
                    program,
                    SourceType.USER_DEFINED,
                )
            elif stack_offset is not None:
                local = LocalVariableImpl(
                    name,
                    parsed,
                    int(stack_offset),
                    program,
                    SourceType.USER_DEFINED,
                )
            else:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    jpype.JObject(None, Address),
                    program,
                    SourceType.USER_DEFINED,
                )
            local = function.addLocalVariable(local, SourceType.USER_DEFINED)
            if comment is not None:
                local.setComment(comment)

        self._with_write(session_id, f"Create local {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_local_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        storage: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=None, storage=storage)
        if variable in function.getParameters():
            raise GhidraBackendError("selected variable is a parameter")

        def mutate() -> None:
            function.removeVariable(variable)

        self._with_write(session_id, f"Remove local {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_comment_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        comment: str | None,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)

        def mutate() -> None:
            variable.setComment(comment)

        self._with_write(session_id, f"Set variable comment {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def stackframe_variable_create(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        stack_offset: int,
        data_type: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        created = None
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = function.getStackFrame().createVariable(
                name,
                int(stack_offset),
                parsed,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Create stackframe variable {name}", mutate)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "variable": self._variable_record(created),
        }

    def stackframe_variable_clear(
        self,
        session_id: str,
        *,
        function_start: int | str,
        stack_offset: int,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            function.getStackFrame().clearVariable(int(stack_offset))

        self._with_write(session_id, f"Clear stackframe variable {stack_offset}", mutate)
        return self.stackframe_variables(session_id, function_start=function.getEntryPoint())

    def stackframe_variables(self, session_id: str, *, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        frame = function.getStackFrame()
        items = [self._variable_record(item) for item in frame.getStackVariables()]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def type_category_list(
        self,
        session_id: str,
        *,
        path: str = "/",
        recursive: bool = False,
    ) -> dict[str, Any]:
        category = self._resolve_category(session_id, path)
        categories = (
            self._walk_categories(category) if recursive else list(category.getCategories())
        )
        items = [self._category_record(item) for item in categories]
        return {
            "session_id": session_id,
            "path": str(category.getCategoryPath()),
            "recursive": recursive,
            "count": len(items),
            "items": items,
        }

    def type_category_create(self, session_id: str, *, path: str) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import CategoryPath

            created = (
                self._get_program(session_id)
                .getDataTypeManager()
                .createCategory(CategoryPath(self._normalize_category_path(path)))
            )

        self._with_write(session_id, f"Create category {path}", mutate)
        return {"session_id": session_id, "category": self._category_record(created)}

    def type_archives_list(self, session_id: str) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        items = [
            {
                "name": dtm.getName(),
                "universal_id": None
                if dtm.getUniversalID() is None
                else int(dtm.getUniversalID().getValue()),
                "kind": "current_program",
            }
        ]
        items.extend(
            {
                "name": archive.getName(),
                "universal_id": int(archive.getSourceArchiveID().getValue()),
                "kind": "source_archive",
            }
            for archive in dtm.getSourceArchives()
        )
        return {"session_id": session_id, "count": len(items), "items": items}

    def type_source_archives_list(self, session_id: str) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        items = [self._source_archive_record(item) for item in dtm.getSourceArchives()]
        return {"session_id": session_id, "count": len(items), "items": items}

    def type_get_by_id(
        self,
        session_id: str,
        *,
        data_type_id: int | None = None,
        universal_id: int | None = None,
        source_archive_id: int | None = None,
    ) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        data_type = None
        if data_type_id is not None:
            with suppress(Exception):
                data_type = dtm.getDataType(int(data_type_id))
        if data_type is None and universal_id is not None:
            from ghidra.util import UniversalID

            data_type = dtm.findDataTypeForID(UniversalID(int(universal_id)))
        if data_type is None and universal_id is not None and source_archive_id is not None:
            from ghidra.util import UniversalID

            source_archive = dtm.getSourceArchive(UniversalID(int(source_archive_id)))
            if source_archive is not None:
                data_type = dtm.getDataType(source_archive, UniversalID(int(universal_id)))
        if data_type is None:
            raise GhidraBackendError("type not found")
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def layout_struct_get(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        return {
            "session_id": session_id,
            "type": self._data_type_record(struct),
            "components": self._components_record(struct),
        }

    def layout_struct_resize(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        length: int,
    ) -> dict[str, Any]:
        if length < 0:
            raise GhidraBackendError("length must be >= 0")
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )

        def mutate() -> None:
            struct.setLength(int(length))

        self._with_write(session_id, f"Resize struct {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_replace(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int,
        data_type: str,
        length: int | None = None,
        field_name: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        parsed = self._parse_data_type(session_id, data_type)
        component_length = length if length is not None else max(1, int(parsed.getLength()))

        def mutate() -> None:
            struct.replaceAtOffset(int(offset), parsed, int(component_length), field_name, comment)

        self._with_write(session_id, f"Replace struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_clear(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )

        def mutate() -> None:
            struct.clearAtOffset(int(offset))

        self._with_write(session_id, f"Clear struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_comment_set(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int | None = None,
        ordinal: int | None = None,
        field_name: str | None = None,
        comment: str | None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        component = self._resolve_component(
            struct, offset=offset, ordinal=ordinal, field_name=field_name
        )

        def mutate() -> None:
            component.setComment(comment)

        self._with_write(session_id, f"Comment struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_bitfield_add(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        byte_offset: int,
        byte_width: int,
        bit_offset: int,
        data_type: str,
        bit_size: int,
        field_name: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            struct.insertBitFieldAt(
                int(byte_offset),
                int(byte_width),
                int(bit_offset),
                parsed,
                int(bit_size),
                field_name,
                comment,
            )

        self._with_write(session_id, f"Add bitfield {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_union_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                UnionDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            created = dtm.addDataType(
                UnionDataType(CategoryPath(self._normalize_category_path(category)), name, dtm),
                DataTypeConflictHandler.DEFAULT_HANDLER,
            )

        self._with_write(session_id, f"Create union {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def layout_union_member_add(
        self,
        session_id: str,
        *,
        union_path: str | None = None,
        union_name: str | None = None,
        field_name: str | None = None,
        data_type: str,
        length: int | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        union = self._require_union(
            self._resolve_data_type(session_id, path=union_path, name=union_name)
        )
        parsed = self._parse_data_type(session_id, data_type)
        member_length = length if length is not None else max(1, int(parsed.getLength()))

        def mutate() -> None:
            union.add(parsed, int(member_length), field_name, comment)

        self._with_write(session_id, f"Add union member {union.getName()}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(union),
            "components": self._components_record(union),
        }

    def layout_union_member_remove(
        self,
        session_id: str,
        *,
        union_path: str | None = None,
        union_name: str | None = None,
        ordinal: int | None = None,
        field_name: str | None = None,
    ) -> dict[str, Any]:
        union = self._require_union(
            self._resolve_data_type(session_id, path=union_path, name=union_name)
        )
        component = self._resolve_component(
            union, offset=None, ordinal=ordinal, field_name=field_name
        )

        def mutate() -> None:
            union.delete(int(component.getOrdinal()))

        self._with_write(session_id, f"Remove union member {union.getName()}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(union),
            "components": self._components_record(union),
        }

    def layout_enum_member_remove(
        self,
        session_id: str,
        *,
        enum_path: str | None = None,
        enum_name: str | None = None,
        name: str,
    ) -> dict[str, Any]:
        enum_type = self._require_enum(
            self._resolve_data_type(session_id, path=enum_path, name=enum_name)
        )

        def mutate() -> None:
            enum_type.remove(name)

        self._with_write(session_id, f"Remove enum member {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(enum_type)}

    def layout_inspect_components(
        self,
        session_id: str,
        *,
        path: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)
        if not hasattr(data_type, "getComponents"):
            raise GhidraBackendError("target type does not expose components")
        return {
            "session_id": session_id,
            "type": self._data_type_record(data_type),
            "components": self._components_record(data_type),
        }

    def layout_struct_fill_from_decompiler(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        create_new_structure: bool = True,
        create_class_if_needed: bool = False,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=ordinal,
            storage=storage,
        )
        if high_symbol is None or high_symbol.getHighVariable() is None:
            raise GhidraBackendError("decompiler symbol not found")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.app.decompiler.util import FillOutStructureHelper

            helper = FillOutStructureHelper(
                self._get_program(session_id),
                self._pyghidra.task_monitor(timeout_secs),
            )
            created = helper.processStructure(
                high_symbol.getHighVariable(),
                function,
                bool(create_new_structure),
                bool(create_class_if_needed),
                self._get_decompiler(session_id),
            )
            if created is None:
                raise GhidraBackendError("failed to create structure from decompiler usage")

        self._with_write(session_id, f"Fill struct from {name}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(created),
            "components": self._components_record(created),
        }
