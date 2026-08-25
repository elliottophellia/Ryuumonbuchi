"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import base64
from collections.abc import Callable, Iterable
from contextlib import suppress
from typing import Any

from .backend_analysis import _AnalysisMixin
from .backend_core import _BackendCore
from .backend_program import _ProgramMixin
from .backend_records import _RecordMixin
from .backend_resolvers import _ResolverMixin
from .backend_state import (
    DEFAULT_ANALYSIS_TIMEOUT,
    MAX_MEMORY_READ_BYTES,
    BackendConfig,
    GhidraBackendError,
    SessionRecord,
    TaskRecord,
)

__all__ = [
    "DEFAULT_ANALYSIS_TIMEOUT",
    "MAX_MEMORY_READ_BYTES",
    "BackendConfig",
    "GhidraBackendError",
    "SessionRecord",
    "TaskRecord",
]


class GhidraBackend(_BackendCore, _RecordMixin, _ResolverMixin, _ProgramMixin, _AnalysisMixin):
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

    def binary_symbols(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_dynamic: bool = False,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbol_table = self._get_program(session_id).getSymbolTable()
        symbols = list(symbol_table.getAllSymbols(include_dynamic))
        if query:
            needle = query.lower()
            symbols = [sym for sym in symbols if needle in sym.getName(True).lower()]
        items = [self._symbol_record(sym) for sym in symbols[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(symbols),
            "count": len(items),
            "items": items,
        }

    def binary_strings(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        program = self._get_program(session_id)
        strings = list(self._iter_strings(program))
        if query:
            needle = query.lower()
            strings = [item for item in strings if needle in item["value"].lower()]
        items = strings[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(strings),
            "count": len(items),
            "items": items,
        }

    def binary_imports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbols = list(self._get_program(session_id).getSymbolTable().getExternalSymbols())
        items = [self._symbol_record(sym) for sym in symbols[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(symbols),
            "count": len(items),
            "items": items,
        }

    def binary_exports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbol_table = self._get_program(session_id).getSymbolTable()
        addrs = list(symbol_table.getExternalEntryPointIterator())
        items = []
        for addr in addrs[offset : offset + limit]:
            symbol = symbol_table.getPrimarySymbol(addr)
            items.append(
                {
                    "address": self._addr_str(addr),
                    "symbol": self._symbol_record(symbol) if symbol is not None else None,
                }
            )
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(addrs),
            "count": len(items),
            "items": items,
        }

    def binary_memory_blocks(self, session_id: str) -> dict[str, Any]:
        blocks = list(self._get_program(session_id).getMemory().getBlocks())
        items = [
            {
                "name": block.getName(),
                "start": self._addr_str(block.getStart()),
                "end": self._addr_str(block.getEnd()),
                "length": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "comment": block.getComment(),
            }
            for block in blocks
        ]
        return {"session_id": session_id, "count": len(items), "items": items}

    def binary_data(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        listing = self._get_program(session_id).getListing()
        data_items = list(
            listing.getDefinedData(
                self._get_program(session_id).getMemory().getAllInitializedAddressSet(), True
            )
        )
        items = [self._data_record(data) for data in data_items[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(data_items),
            "count": len(items),
            "items": items,
        }

    def disasm_function(
        self,
        session_id: str,
        address: int | str,
        *,
        limit: int = 500,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        items = self._disassemble_instructions(
            self._get_program(session_id).getListing().getInstructions(function.getBody(), True),
            limit,
        )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def disasm_range(
        self,
        session_id: str,
        start: int | str,
        *,
        length: int,
        limit: int = 200,
    ) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        start_addr = self._coerce_address(session_id, start, "start")
        end_addr = start_addr.add(length - 1)
        from ghidra.program.model.address import AddressSet

        address_set = AddressSet(start_addr, end_addr)
        instructions = self._get_program(session_id).getListing().getInstructions(address_set, True)
        items = self._disassemble_instructions(instructions, limit)
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "length": length,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def xref_to(
        self,
        session_id: str,
        address: int | str | None = None,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError("address cannot be combined with start/end")
            addr = self._coerce_address(session_id, address, "address")
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesTo(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {
                "session_id": session_id,
                "address": self._addr_str(addr),
                "count": len(items),
                "items": items,
            }
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        if address_set is None:
            raise GhidraBackendError("address or start is required")
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for to_addr in manager.getReferenceDestinationIterator(address_set, True):
            for ref in manager.getReferencesTo(to_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def xref_from(
        self,
        session_id: str,
        address: int | str | None = None,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError("address cannot be combined with start/end")
            addr = self._coerce_address(session_id, address, "address")
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesFrom(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {
                "session_id": session_id,
                "address": self._addr_str(addr),
                "count": len(items),
                "items": items,
            }
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        if address_set is None:
            raise GhidraBackendError("address or start is required")
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for from_addr in manager.getReferenceSourceIterator(address_set, True):
            for ref in manager.getReferencesFrom(from_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

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

    def annotation_comment_get(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        comment_type: str = "eol",
        function_start: int | str | None = None,
        scope: str = "listing",
    ) -> dict[str, Any]:
        if scope == "function":
            function = self._resolve_function(session_id, function_start or address)
            if comment_type == "repeatable":
                comment = function.getRepeatableComment()
            else:
                comment = function.getComment()
            return {
                "session_id": session_id,
                "scope": scope,
                "function_start": self._addr_str(function.getEntryPoint()),
                "comment_type": comment_type,
                "comment": comment,
            }
        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        addr = self._coerce_address(session_id, address, "address")
        listing = self._get_program(session_id).getListing()
        comment = listing.getComment(self._comment_type(comment_type), addr)
        return {
            "session_id": session_id,
            "scope": scope,
            "address": self._addr_str(addr),
            "comment_type": comment_type,
            "comment": comment,
        }

    def annotation_comment_set(
        self,
        session_id: str,
        *,
        comment: str | None,
        address: int | str | None = None,
        comment_type: str = "eol",
        function_start: int | str | None = None,
        scope: str = "listing",
    ) -> dict[str, Any]:
        if scope == "function":
            function = self._resolve_function(session_id, function_start or address)

            def mutate() -> None:
                if comment_type == "repeatable":
                    function.setRepeatableComment(comment)
                else:
                    function.setComment(comment)

            self._with_write(session_id, f"Set function comment {function.getName()}", mutate)
            return self.annotation_comment_get(
                session_id,
                function_start=function.getEntryPoint(),
                comment_type=comment_type,
                scope=scope,
            )

        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getListing().setComment(
                addr, self._comment_type(comment_type), comment
            )

        self._with_write(session_id, f"Set comment {self._addr_str(addr)}", mutate)
        return self.annotation_comment_get(
            session_id,
            address=addr,
            comment_type=comment_type,
            scope=scope,
        )

    def annotation_symbol_rename(
        self,
        session_id: str,
        *,
        address: int | str,
        new_name: str,
        old_name: str | None = None,
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        symbol = self._resolve_symbol(session_id, address, name=old_name)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            symbol.setName(new_name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def annotation_symbol_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str,
        make_primary: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        addr = self._coerce_address(session_id, address, "address")
        created: Any = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = self._get_record(session_id).flat_api.createLabel(
                addr, name, make_primary, SourceType.USER_DEFINED
            )

        self._with_write(session_id, f"Create symbol {name}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(created)}

    def annotation_symbol_delete(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().removeSymbolSpecial(symbol)

        deleted_name = symbol.getName(True)
        self._with_write(session_id, f"Delete symbol {deleted_name}", mutate)
        return {
            "session_id": session_id,
            "deleted": True,
            "address": self._addr_str(symbol.getAddress()),
            "name": deleted_name,
        }

    def memory_read(self, session_id: str, address: int | str, *, length: int) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        if length > MAX_MEMORY_READ_BYTES:
            raise GhidraBackendError(f"length must be <= {MAX_MEMORY_READ_BYTES}")
        addr = self._coerce_address(session_id, address, "address")
        raw = bytes(self._get_record(session_id).flat_api.getBytes(addr, length))
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "length": length,
            "data_base64": base64.b64encode(raw).decode("ascii"),
            "data_hex": raw.hex(),
        }

    def memory_write(
        self,
        session_id: str,
        address: int | str,
        *,
        data_base64: str | None = None,
        data_hex: str | None = None,
    ) -> dict[str, Any]:
        payload = self._decode_payload(data_base64=data_base64, data_hex=data_hex)
        if len(payload) > MAX_MEMORY_READ_BYTES:
            raise GhidraBackendError(
                f"write payload too large ({len(payload)} bytes); max is {MAX_MEMORY_READ_BYTES}"
            )
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> int:
            from jpype.types import JArray, JByte

            written = (
                self._get_program(session_id).getMemory().setBytes(addr, JArray(JByte)(payload))
            )
            return len(payload) if written is None else int(written)

        written = self._with_write(session_id, f"Write memory {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "requested": len(payload),
            "written": written,
        }

    def data_typed_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        data = self._get_program(session_id).getListing().getDefinedDataContaining(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "defined": data is not None,
            "data": self._data_record(data) if data is not None else None,
        }

    def data_create(
        self,
        session_id: str,
        address: int | str,
        *,
        data_type: str,
        length: int | None = None,
        clear_existing: bool = True,
    ) -> dict[str, Any]:
        if not data_type:
            raise GhidraBackendError("data_type is required")
        addr = self._coerce_address(session_id, address, "address")
        parsed = self._parse_data_type(session_id, data_type)
        created = None

        def mutate() -> None:
            nonlocal created
            listing = self._get_program(session_id).getListing()
            if clear_existing:
                end_addr = addr if length is None or length <= 1 else addr.add(length - 1)
                listing.clearCodeUnits(addr, end_addr, False)
            if length is None:
                created = listing.createData(addr, parsed)
            else:
                created = listing.createData(addr, parsed, length)

        self._with_write(session_id, f"Create data {data_type}", mutate)
        return {"session_id": session_id, "data": self._data_record(created)}

    def data_clear(self, session_id: str, address: int | str, *, length: int = 1) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        addr = self._coerce_address(session_id, address, "address")
        end_addr = addr.add(length - 1)

        def mutate() -> None:
            self._get_program(session_id).getListing().clearCodeUnits(addr, end_addr, False)

        self._with_write(session_id, f"Clear data {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "length": length,
            "cleared": True,
        }

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

    def symbol_by_name(
        self,
        session_id: str,
        name: str,
        *,
        exact: bool = False,
        limit: int = 20,
        include_dynamic: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        symbols = list(
            self._get_program(session_id).getSymbolTable().getAllSymbols(include_dynamic)
        )
        if exact:
            matched = [
                symbol
                for symbol in symbols
                if symbol.getName(True) == name or symbol.getName() == name
            ]
        else:
            needle = name.lower()
            matched = [symbol for symbol in symbols if needle in symbol.getName(True).lower()]
        items = [self._symbol_record(symbol) for symbol in matched[:limit]]
        return {
            "session_id": session_id,
            "query": name,
            "exact": exact,
            "limit": limit,
            "total": len(matched),
            "count": len(items),
            "items": items,
        }

    def address_resolve(self, session_id: str, query: int | str) -> dict[str, Any]:
        if query is None or (isinstance(query, str) and not query.strip()):
            raise GhidraBackendError("query is required")
        payload: dict[str, Any] = {
            "session_id": session_id,
            "query": query,
            "resolved": False,
        }
        with suppress(GhidraBackendError):
            addr = self._coerce_address(session_id, query, "query")
            payload["resolved"] = True
            payload["address"] = self._addr_str(addr)
            with suppress(GhidraBackendError):
                payload["function"] = self.binary_get_function_at(session_id, addr)["function"]
            symbols = list(self._get_program(session_id).getSymbolTable().getSymbols(addr))
            payload["symbols"] = [self._symbol_record(symbol) for symbol in symbols]
            payload["data"] = self.data_typed_at(session_id, addr)["data"]
            return payload

        if not isinstance(query, str):
            raise GhidraBackendError("query must be a string or address")

        symbols = self.symbol_by_name(session_id, query, exact=True, limit=50)["items"]
        if not symbols:
            symbols = self.symbol_by_name(session_id, query, exact=False, limit=50)["items"]
        functions = self.function_by_name(session_id, query, exact=True, limit=50)["items"]
        if not functions:
            functions = self.function_by_name(session_id, query, exact=False, limit=50)["items"]
        payload["symbols"] = symbols
        payload["functions"] = functions
        addresses = sorted(
            {
                item["address"]
                for item in symbols
                if isinstance(item, dict) and item.get("address") is not None
            }
            | {
                item["entry_point"]
                for item in functions
                if isinstance(item, dict) and item.get("entry_point") is not None
            }
        )
        if addresses:
            payload["resolved"] = True
            payload["address"] = addresses[0]
            with suppress(GhidraBackendError):
                payload["data"] = self.data_typed_at(session_id, addresses[0])["data"]
        return payload

    def search_text(
        self,
        session_id: str,
        text: str,
        *,
        case_sensitive: bool = False,
        defined_strings_only: bool = False,
        encoding: str = "utf-8",
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not text:
            raise GhidraBackendError("text is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        try:
            needle_bytes = text.encode(encoding)
        except LookupError as exc:
            raise GhidraBackendError(f"unknown encoding: {encoding}") from exc
        except UnicodeEncodeError as exc:
            raise GhidraBackendError(str(exc)) from exc
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        items: list[dict[str, Any]] = []
        seen_addresses: set[str] = set()
        haystack = list(self._iter_strings(self._get_program(session_id), address_set=address_set))
        for item in haystack:
            candidate = item["value"]
            matched = text in candidate if case_sensitive else text.lower() in candidate.lower()
            if matched:
                record = {"kind": "defined_string", **item}
                items.append(record)
                seen_addresses.add(record["address"])
                if len(items) >= limit:
                    break
        if not defined_strings_only and len(items) < limit:
            for addr in self._find_byte_matches(
                session_id,
                needle_bytes,
                limit - len(items),
                address_set=address_set,
            ):
                addr_text = self._addr_str(addr)
                if addr_text in seen_addresses:
                    continue
                items.append(
                    {
                        "kind": "memory_match",
                        "address": addr_text,
                        "text": text,
                        "encoding": encoding,
                    }
                )
                seen_addresses.add(addr_text)
                if len(items) >= limit:
                    break
        return {
            "session_id": session_id,
            "query": text,
            "case_sensitive": case_sensitive,
            "defined_strings_only": defined_strings_only,
            "encoding": encoding,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_bytes(
        self,
        session_id: str,
        *,
        pattern_base64: str | None = None,
        pattern_hex: str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        payload = self._decode_payload(data_base64=pattern_base64, data_hex=pattern_hex)
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        matches = self._find_byte_matches(session_id, payload, limit, address_set=address_set)
        items = [
            {"address": self._addr_str(addr), "pattern_hex": payload.hex()} for addr in matches
        ]
        return {
            "session_id": session_id,
            "pattern_hex": payload.hex(),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_constants(
        self,
        session_id: str,
        value: int | str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        scalar_value = int(value, 0) if isinstance(value, str) else int(value)
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        scope = program.getMemory() if address_set is None else address_set
        instructions = listing.getInstructions(scope, True)
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            for operand_index in range(int(instruction.getNumOperands())):
                scalar = None
                with suppress(Exception):
                    scalar = instruction.getScalar(operand_index)
                if scalar is None:
                    continue
                if int(scalar.getValue()) != scalar_value:
                    continue
                items.append(
                    {
                        "address": self._addr_str(instruction.getAddress()),
                        "instruction": instruction.toString(),
                        "operand_index": operand_index,
                        "scalar_value": int(scalar.getValue()),
                        "scalar_hex": hex(int(scalar.getValue())),
                    }
                )
                break
        return {
            "session_id": session_id,
            "query": scalar_value,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_instructions(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        function_start: int | str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not query:
            raise GhidraBackendError("query is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if function_start is not None and start is not None:
            raise GhidraBackendError("function_start cannot be combined with start/end")
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr = None
        end_addr = None
        if function_start is None:
            start_addr, end_addr, address_set = self._optional_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            scope = program.getMemory() if address_set is None else address_set
            instructions = listing.getInstructions(scope, True)
        else:
            function = self._resolve_function(session_id, function_start)
            instructions = listing.getInstructions(function.getBody(), True)
        needle = query if case_sensitive else query.lower()
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            text = instruction.toString()
            haystack = text if case_sensitive else text.lower()
            mnemonic = instruction.getMnemonicString()
            if needle not in haystack and needle not in (
                mnemonic if case_sensitive else mnemonic.lower()
            ):
                continue
            items.append(
                {
                    "address": self._addr_str(instruction.getAddress()),
                    "mnemonic": mnemonic,
                    "text": text,
                    "bytes": bytes(instruction.getBytes()).hex(),
                }
            )
        return {
            "session_id": session_id,
            "query": query,
            "function_start": None
            if function_start is None
            else self._addr_str(self._coerce_address(session_id, function_start, "function_start")),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_pcode(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        function_start: int | str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not query:
            raise GhidraBackendError("query is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if function_start is not None and start is not None:
            raise GhidraBackendError("function_start cannot be combined with start/end")
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr = None
        end_addr = None
        if function_start is None:
            start_addr, end_addr, address_set = self._optional_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            scope = program.getMemory() if address_set is None else address_set
            instructions = listing.getInstructions(scope, True)
        else:
            function = self._resolve_function(session_id, function_start)
            instructions = listing.getInstructions(function.getBody(), True)
        needle = query if case_sensitive else query.lower()
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            for op in instruction.getPcode():
                text = str(op)
                haystack = text if case_sensitive else text.lower()
                mnemonic = op.getMnemonic()
                if needle not in haystack and needle not in (
                    mnemonic if case_sensitive else mnemonic.lower()
                ):
                    continue
                items.append(
                    {
                        "address": self._addr_str(instruction.getAddress()),
                        "instruction": instruction.toString(),
                        "op": self._pcode_op_record(op),
                    }
                )
                if len(items) >= limit:
                    break
        return {
            "session_id": session_id,
            "query": query,
            "function_start": None
            if function_start is None
            else self._addr_str(self._coerce_address(session_id, function_start, "function_start")),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
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

    def patch_assemble(
        self,
        session_id: str,
        *,
        address: int | str,
        assembly: str,
    ) -> dict[str, Any]:
        if not assembly:
            raise GhidraBackendError("assembly is required")
        addr = self._coerce_address(session_id, address, "address")
        assembled: list[dict[str, Any]] = []

        def mutate() -> None:
            nonlocal assembled
            from ghidra.app.plugin.assembler import Assemblers

            assembler = Assemblers.getAssembler(self._get_program(session_id))
            iterator = assembler.assemble(addr, assembly)
            assembled = self._disassemble_instructions(iterator, 128)

        self._with_write(session_id, f"Assemble at {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "assembly": assembly,
            "count": len(assembled),
            "items": assembled,
        }

    def patch_nop(
        self,
        session_id: str,
        *,
        address: int | str,
        count: int = 1,
    ) -> dict[str, Any]:
        if count <= 0:
            raise GhidraBackendError("count must be > 0")
        addr = self._coerce_address(session_id, address, "address")
        program = self._get_program(session_id)
        listing = program.getListing()

        # Resolve the byte span covered by `count` instructions starting at
        # `address`, so we NOP exactly that many bytes regardless of ISA width.
        span_start = addr
        span_end = addr
        cursor = addr
        remaining = count
        while remaining > 0:
            instr = listing.getInstructionAt(cursor)
            if instr is None:
                # Fall back to the current single byte cell if undefined here.
                span_end = cursor
                break
            span_end = instr.getMaxAddress()
            remaining -= 1
            cursor = span_end.add(1)
        span_length = int(span_end.subtract(span_start)) + 1

        # Raw-byte route: the SLEIGH assembler rejects the NOP mnemonic on some
        # language specs (notably x86), and a failed assemble attempt can leave
        # memory half-written via a non-rolling-back transaction. Clearing the
        # conflicting code units then writing the canonical NOP byte is
        # ISA-portable for the common cases (x86 0x90, generic 0x00 fill) and
        # does not depend on the assembler. Use the language's NOP fill byte.
        lang_id = str(program.getLanguageID())
        if lang_id.startswith("x86"):
            nop_byte = 0x90
        elif lang_id.startswith("ARM") or lang_id.startswith("AARCH"):
            # ARM NOP is not a single repeating byte; raw fill would be invalid.
            # Fall back to the assembler for these ISAs where it is required.
            nop_byte = None
        else:
            nop_byte = 0x00

        def mutate_raw() -> dict[str, Any]:
            listing.clearCodeUnits(span_start, span_end, True)
            if nop_byte is None:
                # Assembler-required ISA: emit via the SLEIGH assembler after clear.
                from ghidra.app.plugin.assembler import Assemblers

                assembler = Assemblers.getAssembler(program)
                assembler.assemble(span_start, "\n".join("nop" for _ in range(count)))
                return {"method": "assembler", "bytes": span_length}
            from jpype.types import JArray, JByte

            payload = bytes([nop_byte] * span_length)
            program.getMemory().setBytes(span_start, JArray(JByte)(payload))
            return {"method": "raw_bytes", "nop_byte": nop_byte, "bytes_written": span_length}

        result = self._with_write(session_id, f"NOP at {self._addr_str(span_start)}", mutate_raw)
        return {
            "session_id": session_id,
            "address": self._addr_str(span_start),
            "end": self._addr_str(span_end),
            "bytes_nopped": span_length,
            "count": count,
            "detail": result if isinstance(result, dict) else {"detail": result},
        }

    def patch_branch_invert(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        instruction = self._get_program(session_id).getListing().getInstructionAt(addr)
        if instruction is None:
            raise GhidraBackendError(f"no instruction at {self._addr_str(addr)}")
        text = instruction.toString()
        mnemonic, _, operands = text.partition(" ")
        normalized = mnemonic.upper()
        inverse = {
            "JE": "JNE",
            "JZ": "JNZ",
            "JNE": "JE",
            "JNZ": "JZ",
            "JA": "JBE",
            "JBE": "JA",
            "JAE": "JB",
            "JB": "JAE",
            "JG": "JLE",
            "JLE": "JG",
            "JGE": "JL",
            "JL": "JGE",
            "JS": "JNS",
            "JNS": "JS",
            "JO": "JNO",
            "JNO": "JO",
            "JP": "JNP",
            "JPE": "JPO",
            "JPO": "JPE",
            "JNP": "JP",
            "B.EQ": "B.NE",
            "B.NE": "B.EQ",
            "B.CS": "B.CC",
            "B.HS": "B.LO",
            "B.CC": "B.CS",
            "B.LO": "B.HS",
            "B.MI": "B.PL",
            "B.PL": "B.MI",
            "B.VS": "B.VC",
            "B.VC": "B.VS",
            "B.HI": "B.LS",
            "B.LS": "B.HI",
            "B.GE": "B.LT",
            "B.LT": "B.GE",
            "B.GT": "B.LE",
            "B.LE": "B.GT",
        }.get(normalized)
        if inverse is None:
            raise GhidraBackendError(f"unsupported conditional branch mnemonic: {mnemonic}")
        if mnemonic != mnemonic.upper():
            inverse = inverse.lower()
        assembly = f"{inverse} {operands}".strip()
        payload = self.patch_assemble(session_id, address=addr, assembly=assembly)
        payload["original_instruction"] = text
        return payload

    def bookmark_add(
        self,
        session_id: str,
        *,
        address: int | str,
        category: str,
        comment: str,
        bookmark_type: str = "NOTE",
    ) -> dict[str, Any]:
        if not category:
            raise GhidraBackendError("category is required")
        addr = self._coerce_address(session_id, address, "address")
        created = None

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getBookmarkManager()
                .setBookmark(addr, bookmark_type, category, comment)
            )

        self._with_write(session_id, f"Add bookmark {category}", mutate)
        return {"session_id": session_id, "bookmark": self._bookmark_record(created)}

    def bookmark_list(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        bookmark_type: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        manager = self._get_program(session_id).getBookmarkManager()
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            if bookmark_type:
                bookmarks = list(manager.getBookmarks(addr, bookmark_type))
            else:
                bookmarks = list(manager.getBookmarks(addr))
        elif bookmark_type:
            bookmarks = list(manager.getBookmarksIterator(bookmark_type))
        else:
            bookmarks = list(manager.getBookmarksIterator())
        items = [self._bookmark_record(bookmark) for bookmark in bookmarks[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(bookmarks),
            "count": len(items),
            "items": items,
        }

    def tag_add(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        comment: str = "",
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
            if manager.getFunctionTag(name) is None:
                manager.createFunctionTag(name, comment)
            if not function.addTag(name):
                raise GhidraBackendError(f"failed to add tag '{name}' to function")

        self._with_write(session_id, f"Add tag {name}", mutate)
        return self.tag_list(session_id, function_start=function.getEntryPoint())

    def tag_list(
        self,
        session_id: str,
        *,
        function_start: int | str | None = None,
    ) -> dict[str, Any]:
        if function_start is not None:
            function = self._resolve_function(session_id, function_start)
            tags = sorted(function.getTags(), key=lambda tag: tag.getName())
            return {
                "session_id": session_id,
                "function": self._function_record(function),
                "count": len(tags),
                "items": [self._function_tag_record(tag) for tag in tags],
            }
        manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
        tags = sorted(manager.getAllFunctionTags(), key=lambda tag: tag.getName())
        return {
            "session_id": session_id,
            "count": len(tags),
            "items": [self._function_tag_record(tag) for tag in tags],
        }

    def memory_block_create(
        self,
        session_id: str,
        *,
        name: str,
        address: int | str,
        length: int,
        initialized: bool = True,
        fill: int = 0,
        read: bool = True,
        write: bool = False,
        execute: bool = False,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        addr = self._coerce_address(session_id, address, "address")
        block = None

        def mutate() -> None:
            nonlocal block
            from jpype.types import JByte

            memory = self._get_program(session_id).getMemory()
            if initialized:
                block = memory.createInitializedBlock(
                    name,
                    addr,
                    length,
                    JByte(fill & 0xFF),
                    self._pyghidra.task_monitor(),
                    False,
                )
            else:
                block = memory.createUninitializedBlock(name, addr, length, False)
            block.setRead(read)
            block.setWrite(write)
            block.setExecute(execute)
            if comment is not None:
                block.setComment(comment)

        self._with_write(session_id, f"Create memory block {name}", mutate)
        return {
            "session_id": session_id,
            "block": {
                "name": block.getName(),
                "start": self._addr_str(block.getStart()),
                "end": self._addr_str(block.getEnd()),
                "length": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "comment": block.getComment(),
            },
        }

    def memory_block_remove(
        self,
        session_id: str,
        *,
        name: str | None = None,
        address: int | str | None = None,
    ) -> dict[str, Any]:
        if not name and address is None:
            raise GhidraBackendError("name or address is required")
        memory = self._get_program(session_id).getMemory()
        block = memory.getBlock(name) if name else None
        if block is None and address is not None:
            addr = self._coerce_address(session_id, address, "address")
            block = memory.getBlock(addr)
        if block is None:
            raise GhidraBackendError("memory block not found")
        payload = {
            "name": block.getName(),
            "start": self._addr_str(block.getStart()),
            "end": self._addr_str(block.getEnd()),
        }

        def mutate() -> None:
            memory.removeBlock(block, self._pyghidra.task_monitor())

        self._with_write(session_id, f"Remove memory block {block.getName()}", mutate)
        return {"session_id": session_id, "deleted": True, "block": payload}

    def external_library_list(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getExternalManager()
        items = []
        for library_name in manager.getExternalLibraryNames():
            item = {"name": str(library_name)}
            with suppress(Exception):
                item["path"] = manager.getExternalLibraryPath(library_name)
            items.append(item)
        return {"session_id": session_id, "count": len(items), "items": items}

    def external_location_get(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = None
        if address is not None:
            symbol = self._resolve_symbol(session_id, address, name=name)
        elif name is not None:
            matches = self.symbol_by_name(session_id, name, exact=True, limit=1)["items"]
            if not matches:
                raise GhidraBackendError(f"external symbol '{name}' not found")
            symbol = self._resolve_symbol(session_id, matches[0]["address"], name=name)
        else:
            raise GhidraBackendError("address or name is required")
        location = self._get_program(session_id).getExternalManager().getExternalLocation(symbol)
        if location is None:
            raise GhidraBackendError("symbol does not have an external location")
        payload = {
            "symbol": self._symbol_record(symbol),
            "display": str(location),
        }
        for attr, field_name in (
            ("getLibraryName", "library_name"),
            ("getLabel", "label"),
            ("getAddress", "address"),
            ("getOriginalImportedName", "original_imported_name"),
        ):
            with suppress(Exception):
                value = getattr(location, attr)()
                payload[field_name] = (
                    self._addr_str(value) if field_name == "address" else str(value)
                )
        return {"session_id": session_id, "location": payload}

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

    def listing_code_units_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        offset: int = 0,
        limit: int = 100,
        forward: bool = True,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        listing = self._get_program(session_id).getListing()
        if start is None:
            iterator = listing.getCodeUnits(self._get_program(session_id).getMemory(), forward)
        else:
            start_addr, end_addr, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            iterator = listing.getCodeUnits(address_set, forward)
        code_units = list(iterator)
        items = [self._code_unit_record(item) for item in code_units[offset : offset + limit]]
        payload = {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(code_units),
            "count": len(items),
            "items": items,
        }
        if start is not None:
            payload["start"] = self._addr_str(start_addr)
            payload["end"] = self._addr_str(end_addr)
        return payload

    def listing_code_unit_at(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitAt(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_before(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitBefore(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_after(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitAfter(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_containing(
        self,
        session_id: str,
        *,
        address: int | str,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitContaining(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_clear(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        clear_context: bool = False,
        clear_symbols: bool = False,
        clear_comments: bool = False,
        clear_properties: bool = False,
        clear_functions: bool = False,
        clear_registers: bool = False,
        clear_equates: bool = False,
        clear_user_references: bool = False,
        clear_analysis_references: bool = False,
        clear_import_references: bool = False,
        clear_default_references: bool = False,
        clear_bookmarks: bool = False,
    ) -> dict[str, Any]:
        start_addr, end_addr, address_set = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> bool:
            if clear_context:
                self._get_program(session_id).getListing().clearCodeUnits(
                    start_addr,
                    end_addr,
                    True,
                )
                return True
            return bool(
                self._get_record(session_id).flat_api.clearListing(
                    address_set,
                    True,
                    clear_symbols,
                    clear_comments,
                    clear_properties,
                    clear_functions,
                    clear_registers,
                    clear_equates,
                    clear_user_references,
                    clear_analysis_references,
                    clear_import_references,
                    clear_default_references,
                    clear_bookmarks,
                )
            )

        cleared = self._with_write(
            session_id, f"Clear listing {self._addr_str(start_addr)}", mutate
        )
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "cleared": cleared,
        }

    def listing_disassemble_seed(
        self,
        session_id: str,
        *,
        address: int | str,
        limit: int = 128,
        clear_existing: bool = False,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> bool:
            if clear_existing:
                self._get_program(session_id).getListing().clearCodeUnits(addr, addr, True)
            return bool(self._get_record(session_id).flat_api.disassemble(addr))

        ok = self._with_write(session_id, f"Disassemble seed {self._addr_str(addr)}", mutate)
        instructions = self._get_program(session_id).getListing().getInstructions(addr, True)
        items = self._disassemble_instructions(instructions, limit)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "disassembled": ok,
            "count": len(items),
            "items": items,
        }

    def context_get(
        self,
        session_id: str,
        *,
        register: str,
        address: int | str,
        signed: bool = False,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        addr = self._coerce_address(session_id, address, "address")
        value = self._get_program(session_id).getProgramContext().getValue(reg, addr, signed)
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "address": self._addr_str(addr),
            "signed": signed,
            "value": None if value is None else int(str(value), 10),
        }

    def context_set(
        self,
        session_id: str,
        *,
        register: str,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        value: int | str | None = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> None:
            from java.math import BigInteger

            context = self._get_program(session_id).getProgramContext()
            if clear:
                context.remove(start_addr, end_addr, reg)
                return
            if value is None:
                raise GhidraBackendError("value is required unless clear=true")
            numeric = int(value, 0) if isinstance(value, str) else int(value)
            context.setValue(reg, start_addr, end_addr, BigInteger.valueOf(numeric))

        self._with_write(session_id, f"Set context {reg.getName()}", mutate)
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "cleared": clear,
        }

    def context_ranges(
        self,
        session_id: str,
        *,
        register: str,
        start: int | str | None = None,
        end: int | str | None = None,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        context = self._get_program(session_id).getProgramContext()
        if start is None:
            ranges = list(context.getRegisterValueAddressRanges(reg))
        else:
            start_addr, end_addr, _ = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            ranges = list(context.getRegisterValueAddressRanges(reg, start_addr, end_addr))
        items = [
            {
                "start": self._addr_str(item.getMinAddress()),
                "end": self._addr_str(item.getMaxAddress()),
            }
            for item in ranges
        ]
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "count": len(items),
            "items": items,
        }

    def symbol_primary_set(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)

        def mutate() -> None:
            symbol.setPrimary()

        self._with_write(session_id, f"Set primary symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def namespace_create(
        self,
        session_id: str,
        *,
        name: str,
        parent: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createNamespace(
                self._resolve_namespace(session_id, parent),
                name,
            )

        self._with_write(session_id, f"Create namespace {name}", mutate)
        return {"session_id": session_id, "namespace": self._namespace_record(created)}

    def class_create(
        self,
        session_id: str,
        *,
        name: str,
        parent: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createClass(
                self._resolve_namespace(session_id, parent),
                name,
            )

        self._with_write(session_id, f"Create class {name}", mutate)
        return {"session_id": session_id, "namespace": self._namespace_record(created)}

    def symbol_namespace_move(
        self,
        session_id: str,
        *,
        address: int | str,
        namespace: str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)
        target = self._resolve_namespace(session_id, namespace)

        def mutate() -> None:
            symbol.setNamespace(target)

        self._with_write(session_id, f"Move symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def external_library_create(self, session_id: str, *, name: str) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = (
                self._get_program(session_id)
                .getSymbolTable()
                .createExternalLibrary(
                    name,
                    SourceType.USER_DEFINED,
                )
            )

        self._with_write(session_id, f"Create external library {name}", mutate)
        return {"session_id": session_id, "library": self._namespace_record(created)}

    def external_library_set_path(
        self,
        session_id: str,
        *,
        name: str,
        path: str | None,
        user_defined: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")

        def mutate() -> None:
            self._get_program(session_id).getExternalManager().setExternalPath(
                name,
                path,
                bool(user_defined),
            )

        self._with_write(session_id, f"Set external path {name}", mutate)
        return self.external_library_list(session_id)

    def external_location_create(
        self,
        session_id: str,
        *,
        library_name: str,
        label: str | None = None,
        external_address: int | str | None = None,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getExternalManager()
        location = None

        def mutate() -> None:
            nonlocal location
            from ghidra.program.model.symbol import SourceType

            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            location = manager.addExtLocation(library_name, label, addr, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Create external location {library_name}", mutate)
        return {"session_id": session_id, "location": self._external_location_record(location)}

    def external_function_create(
        self,
        session_id: str,
        *,
        library_name: str,
        name: str,
        external_address: int | str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        manager = self._get_program(session_id).getExternalManager()
        location = None

        def mutate() -> None:
            nonlocal location
            from ghidra.program.model.symbol import SourceType

            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            location = manager.addExtFunction(library_name, name, addr, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Create external function {name}", mutate)
        return {"session_id": session_id, "location": self._external_location_record(location)}

    def external_entrypoint_add(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().addExternalEntryPoint(addr)

        self._with_write(session_id, f"Add external entrypoint {self._addr_str(addr)}", mutate)
        return self.external_entrypoint_list(session_id)

    def external_entrypoint_remove(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().removeExternalEntryPoint(addr)

        self._with_write(session_id, f"Remove external entrypoint {self._addr_str(addr)}", mutate)
        return self.external_entrypoint_list(session_id)

    def external_entrypoint_list(self, session_id: str) -> dict[str, Any]:
        items = [
            self._addr_str(addr)
            for addr in self._get_program(session_id)
            .getSymbolTable()
            .getExternalEntryPointIterator()
        ]
        return {"session_id": session_id, "count": len(items), "items": items}

    def reference_create_memory(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        to_addr = self._coerce_address(session_id, to_address, "to_address")

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addMemoryReference(
                    from_addr,
                    to_addr,
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                    operand_index,
                )
            )

        self._with_write(session_id, f"Add memory reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_stack(
        self,
        session_id: str,
        *,
        from_address: int | str,
        stack_offset: int,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addStackReference(
                    from_addr,
                    operand_index,
                    int(stack_offset),
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                )
            )

        self._with_write(session_id, f"Add stack reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_register(
        self,
        session_id: str,
        *,
        from_address: int | str,
        register: str,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        reg = self._resolve_register(session_id, register)

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addRegisterReference(
                    from_addr,
                    operand_index,
                    reg,
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                )
            )

        self._with_write(session_id, f"Add register reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_external(
        self,
        session_id: str,
        *,
        from_address: int | str,
        library_name: str,
        label: str | None = None,
        external_address: int | str | None = None,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            nonlocal created
            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addExternalReference(
                    from_addr,
                    library_name,
                    label,
                    addr,
                    self._source_type(source_type),
                    operand_index,
                    self._ref_type(reference_type),
                )
            )

        self._with_write(session_id, f"Add external reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_delete(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str | None = None,
        operand_index: int | None = None,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().delete(reference)

        self._with_write(
            session_id, f"Delete reference {self._addr_str(reference.getFromAddress())}", mutate
        )
        return {"session_id": session_id, "deleted": True}

    def reference_clear_from(
        self,
        session_id: str,
        *,
        from_address: int | str,
        end_address: int | str | None = None,
    ) -> dict[str, Any]:
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            manager = self._get_program(session_id).getReferenceManager()
            if end_address is None:
                manager.removeAllReferencesFrom(from_addr)
                return
            manager.removeAllReferencesFrom(
                from_addr,
                self._coerce_address(session_id, end_address, "end_address"),
            )

        self._with_write(session_id, f"Clear references from {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "cleared": True}

    def reference_clear_to(self, session_id: str, *, to_address: int | str) -> dict[str, Any]:
        to_addr = self._coerce_address(session_id, to_address, "to_address")

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().removeAllReferencesTo(to_addr)

        self._with_write(session_id, f"Clear references to {self._addr_str(to_addr)}", mutate)
        return {"session_id": session_id, "cleared": True}

    def reference_primary_set(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().setPrimary(reference, True)

        self._with_write(
            session_id,
            f"Set primary reference {self._addr_str(reference.getFromAddress())}",
            mutate,
        )
        return {"session_id": session_id, "reference": self._reference_record(reference)}

    def reference_association_set(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
        symbol_address: int | str,
        symbol_name: str | None = None,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )
        symbol = self._resolve_symbol(session_id, symbol_address, name=symbol_name)

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().setAssociation(symbol, reference)

        self._with_write(
            session_id, f"Associate reference {self._addr_str(reference.getFromAddress())}", mutate
        )
        return {
            "session_id": session_id,
            "reference": self._reference_record(reference),
            "symbol": self._symbol_record(symbol),
        }

    def reference_association_remove(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().removeAssociation(reference)

        self._with_write(
            session_id,
            f"Remove reference association {self._addr_str(reference.getFromAddress())}",
            mutate,
        )
        return {"session_id": session_id, "reference": self._reference_record(reference)}

    def equate_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str,
        value: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        addr = self._coerce_address(session_id, address, "address")
        numeric = int(value, 0) if isinstance(value, str) else int(value)
        equate = None

        def mutate() -> None:
            nonlocal equate
            table = self._get_program(session_id).getEquateTable()
            equate = table.getEquate(name)
            if equate is None:
                equate = table.createEquate(name, numeric)
            equate.addReference(addr, operand_index)

        self._with_write(session_id, f"Create equate {name}", mutate)
        return {"session_id": session_id, "equate": self._equate_record(equate)}

    def equate_list(
        self,
        session_id: str,
        *,
        name: str | None = None,
        address: int | str | None = None,
        operand_index: int | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        table = self._get_program(session_id).getEquateTable()
        if name is not None:
            equates = [] if table.getEquate(name) is None else [table.getEquate(name)]
        elif address is not None:
            addr = self._coerce_address(session_id, address, "address")
            equates = (
                list(table.getEquates(addr))
                if operand_index is None
                else list(table.getEquates(addr, operand_index))
            )
        else:
            equates = list(table.getEquates())
        items = [self._equate_record(item) for item in equates[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(equates),
            "count": len(items),
            "items": items,
        }

    def equate_delete(
        self,
        session_id: str,
        *,
        name: str,
        address: int | str | None = None,
        operand_index: int | None = None,
    ) -> dict[str, Any]:
        table = self._get_program(session_id).getEquateTable()
        equate = table.getEquate(name)
        if equate is None:
            raise GhidraBackendError(f"equate not found: {name}")

        def mutate() -> None:
            if address is not None:
                addr = self._coerce_address(session_id, address, "address")
                if operand_index is None:
                    for ref in list(equate.getReferences(addr)):
                        equate.removeReference(ref.getAddress(), ref.getOpIndex())
                else:
                    equate.removeReference(addr, operand_index)
            if address is None or equate.getReferenceCount() == 0:
                table.removeEquate(name)

        self._with_write(session_id, f"Delete equate {name}", mutate)
        return {"session_id": session_id, "deleted": True, "name": name}

    def equate_clear_range(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> int:
            removed = 0
            table = self._get_program(session_id).getEquateTable()
            for equate in list(table.getEquates()):
                for ref in list(equate.getReferences()):
                    ref_addr = ref.getAddress()
                    if ref_addr.compareTo(start_addr) < 0 or ref_addr.compareTo(end_addr) > 0:
                        continue
                    equate.removeReference(ref_addr, ref.getOpIndex())
                    removed += 1
                if equate.getReferenceCount() == 0:
                    table.removeEquate(equate.getName())
            return removed

        removed = self._with_write(
            session_id, f"Clear equates {self._addr_str(start_addr)}", mutate
        )
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "removed": removed,
        }

    def comment_get_all(
        self,
        session_id: str,
        *,
        address: int | str,
        include_function: bool = True,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        comments = {
            name: self.annotation_comment_get(session_id, address=addr, comment_type=name)[
                "comment"
            ]
            for name in ("plate", "pre", "eol", "post", "repeatable")
        }
        payload: dict[str, Any] = {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "comments": comments,
        }
        if include_function:
            with suppress(GhidraBackendError):
                function = self._resolve_function(session_id, addr)
                payload["function"] = {
                    "entry_point": self._addr_str(function.getEntryPoint()),
                    "comment": function.getComment(),
                    "repeatable_comment": function.getRepeatableComment(),
                }
        return payload

    def comment_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        comment_type: str | None = None,
        query: str | None = None,
        case_sensitive: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        program = self._get_program(session_id)
        listing = program.getListing()
        if start is None:
            address_set = program.getMemory().getAllInitializedAddressSet()
        else:
            _, _, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
        if comment_type is None:
            iterator = listing.getCommentAddressIterator(address_set, True)
        else:
            iterator = listing.getCommentAddressIterator(
                self._comment_type(comment_type),
                address_set,
                True,
            )
        addresses = list(iterator)
        if query:
            needle = query if case_sensitive else query.lower()
            matched: list[dict[str, Any]] = []
            for addr in addresses:
                payload = self.comment_get_all(session_id, address=addr, include_function=False)
                comments = [value for value in payload["comments"].values() if value]
                if not any(
                    needle in (comment if case_sensitive else comment.lower())
                    for comment in comments
                ):
                    continue
                matched.append(payload)
            total = len(matched)
            items = matched[offset : offset + limit]
        else:
            total = len(addresses)
            items = [
                self.comment_get_all(session_id, address=addr, include_function=False)
                for addr in addresses[offset : offset + limit]
            ]
        return {
            "session_id": session_id,
            "query": query,
            "case_sensitive": case_sensitive,
            "offset": offset,
            "limit": limit,
            "total": total,
            "count": len(items),
            "items": items,
        }

    def bookmark_remove(
        self,
        session_id: str,
        *,
        address: int | str,
        bookmark_type: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> int:
            manager = self._get_program(session_id).getBookmarkManager()
            bookmarks = (
                list(manager.getBookmarks(addr, bookmark_type))
                if bookmark_type
                else list(manager.getBookmarks(addr))
            )
            removed = 0
            for bookmark in bookmarks:
                if category is not None and bookmark.getCategory() != category:
                    continue
                manager.removeBookmark(bookmark)
                removed += 1
            return removed

        removed = self._with_write(session_id, f"Remove bookmarks {self._addr_str(addr)}", mutate)
        return {"session_id": session_id, "removed": removed}

    def bookmark_clear(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        bookmark_type: str | None = None,
    ) -> dict[str, Any]:
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> int:
            manager = self._get_program(session_id).getBookmarkManager()
            removed = 0
            iterator = (
                manager.getBookmarksIterator(bookmark_type)
                if bookmark_type
                else manager.getBookmarksIterator()
            )
            for bookmark in list(iterator):
                addr = bookmark.getAddress()
                if addr.compareTo(start_addr) < 0 or addr.compareTo(end_addr) > 0:
                    continue
                manager.removeBookmark(bookmark)
                removed += 1
            return removed

        removed = self._with_write(
            session_id, f"Clear bookmarks {self._addr_str(start_addr)}", mutate
        )
        return {"session_id": session_id, "removed": removed}

    def tag_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        tag = None
        for candidate in function.getTags():
            if candidate.getName() == name:
                tag = candidate
                break
        if tag is None:
            raise GhidraBackendError(f"tag '{name}' not found")

        def mutate() -> None:
            function.removeTag(name)

        self._with_write(session_id, f"Remove tag {name}", mutate)
        return self.tag_list(session_id, function_start=function.getEntryPoint())

    def tag_stats(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
        functions = list(self._get_program(session_id).getFunctionManager().getFunctions(True))
        items = []
        for tag in sorted(manager.getAllFunctionTags(), key=lambda item: item.getName()):
            count = sum(1 for func in functions if tag in func.getTags())
            items.append({"tag": self._function_tag_record(tag), "function_count": count})
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_file_list(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        items = [self._source_file_record(item) for item in manager.getAllSourceFiles()]
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_file_add(
        self,
        session_id: str,
        *,
        path: str,
        id_type: str | None = None,
        identifier_hex: str | None = None,
    ) -> dict[str, Any]:
        source_file = self._source_file_from_args(
            path=path, id_type=id_type, identifier_hex=identifier_hex
        )

        def mutate() -> None:
            self._get_program(session_id).getSourceFileManager().addSourceFile(source_file)

        self._with_write(session_id, f"Add source file {path}", mutate)
        return self.source_file_list(session_id)

    def source_file_remove(
        self,
        session_id: str,
        *,
        path: str,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)

        def mutate() -> None:
            manager.removeSourceFile(source_file)

        self._with_write(session_id, f"Remove source file {path}", mutate)
        return self.source_file_list(session_id)

    def source_map_list(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        path: str | None = None,
        min_line: int | None = None,
        max_line: int | None = None,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            entries = list(manager.getSourceMapEntries(addr))
        elif path is not None:
            source_file = self._find_source_file(manager, path)
            entries = list(
                manager.getSourceMapEntries(source_file, min_line or 0, max_line or 2**31 - 1)
            )
        else:
            entries = []
            for source_file in manager.getMappedSourceFiles():
                entries.extend(
                    list(
                        manager.getSourceMapEntries(
                            source_file, min_line or 0, max_line or 2**31 - 1
                        )
                    )
                )
        items = [self._source_map_entry_record(item) for item in entries]
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_map_add(
        self,
        session_id: str,
        *,
        path: str,
        line_number: int,
        base_address: int | str,
        length: int,
    ) -> dict[str, Any]:
        if line_number <= 0:
            raise GhidraBackendError("line_number must be > 0")
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)
        base_addr = self._coerce_address(session_id, base_address, "base_address")

        def mutate() -> None:
            manager.addSourceMapEntry(source_file, line_number, base_addr, length)

        self._with_write(session_id, f"Add source map {path}", mutate)
        return self.source_map_list(session_id, path=path)

    def source_map_remove(
        self,
        session_id: str,
        *,
        path: str,
        line_number: int,
        base_address: int | str,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)
        base_addr = self._coerce_address(session_id, base_address, "base_address")
        entry = None
        for candidate in manager.getSourceMapEntries(source_file, line_number, line_number):
            if str(candidate.getBaseAddress()) == self._addr_str(base_addr):
                entry = candidate
                break
        if entry is None:
            raise GhidraBackendError("source map entry not found")

        def mutate() -> None:
            manager.removeSourceMapEntry(entry)

        self._with_write(session_id, f"Remove source map {path}", mutate)
        return self.source_map_list(session_id, path=path)

    def relocation_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
    ) -> dict[str, Any]:
        table = self._get_program(session_id).getRelocationTable()
        if start is None:
            relocations = list(table.getRelocations())
        else:
            _, _, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            relocations = list(table.getRelocations(address_set))
        items = [self._relocation_record(item) for item in relocations]
        return {"session_id": session_id, "count": len(items), "items": items}

    def relocation_add(
        self,
        session_id: str,
        *,
        address: int | str,
        status: str = "APPLIED",
        type: int = 0,
        values: list[int] | None = None,
        byte_length: int = 0,
        symbol_name: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            from ghidra.program.model.reloc import Relocation
            from jpype.types import JArray, JLong

            valid_statuses = [str(item) for item in Relocation.Status.values()]
            if status not in valid_statuses:
                raise GhidraBackendError(
                    "unsupported relocation status: "
                    f"{status}; use one of: {', '.join(valid_statuses)}"
                )
            relocation_status = getattr(Relocation.Status, status)
            self._get_program(session_id).getRelocationTable().add(
                addr,
                relocation_status,
                int(type),
                JArray(JLong)(values or []),
                int(byte_length),
                symbol_name,
            )

        self._with_write(session_id, f"Add relocation {self._addr_str(addr)}", mutate)
        return self.relocation_list(session_id, start=addr, end=addr)

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

    def _disassemble_instructions(self, instructions: Any, limit: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            items.append(
                {
                    "address": self._addr_str(instruction.getAddress()),
                    "mnemonic": instruction.getMnemonicString(),
                    "text": instruction.toString(),
                    "bytes": bytes(instruction.getBytes()).hex(),
                }
            )
        return items

    def _iter_strings(
        self,
        program: Any,
        *,
        address_set: Any | None = None,
    ) -> Iterable[dict[str, Any]]:
        from ghidra.program.model.data import StringDataInstance
        from ghidra.program.util import DefinedDataIterator

        iterator = DefinedDataIterator.byDataInstance(
            program,
            lambda data: (
                StringDataInstance.getStringDataInstance(data) != StringDataInstance.NULL_INSTANCE
            ),
        )
        for data in iterator:
            if address_set is not None and not address_set.contains(data.getAddress()):
                continue
            instance = StringDataInstance.getStringDataInstance(data)
            yield {
                "address": self._addr_str(data.getAddress()),
                "length": int(data.getLength()),
                "value": instance.getStringValue(),
                "data_type": data.getDataType().getPathName(),
            }

    def _find_byte_matches(
        self,
        session_id: str,
        payload: bytes,
        limit: int,
        *,
        address_set: Any | None = None,
    ) -> list[Any]:
        if limit <= 0:
            return []
        # Ghidra's findBytes treats the byteString as a regex over bytes, where
        # literal bytes are written as \xNN escapes. Space-separated plain hex
        # (e.g. "de ad be ef") is matched as the literal ASCII characters and
        # never matches binary data, so the pattern must be \x-escaped.
        pattern = "".join(f"\\x{byte:02x}" for byte in payload)
        search_base = (
            self._get_program(session_id).getMemory() if address_set is None else address_set
        )
        try:
            results = self._get_record(session_id).flat_api.findBytes(
                search_base, pattern, limit, 1
            )
        except Exception as exc:
            raise GhidraBackendError(f"byte search failed: {exc}") from exc
        return [] if results is None else list(results)
