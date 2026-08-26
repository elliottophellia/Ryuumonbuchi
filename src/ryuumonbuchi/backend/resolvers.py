"""Backend responsibility mixin: _ResolverMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import re
from contextlib import suppress
from pathlib import Path
from typing import Any

from .state import GhidraBackendError


class _ResolverMixin:
    def _resolve_function(self, session_id: str, function_start: int | str | None) -> Any:
        if function_start is None:
            raise GhidraBackendError("function_start is required")
        addr = self._coerce_address(session_id, function_start, "function_start")
        manager = self._get_program(session_id).getFunctionManager()
        function = manager.getFunctionAt(addr)
        if function is None:
            function = manager.getFunctionContaining(addr)
        if function is None:
            normalized = self._addr_str(addr)
            hint = self._function_neighbor_hint(manager, addr)
            raise GhidraBackendError(f"no function found at {normalized}; {hint}")
        return function
    def _function_neighbor_hint(self, manager: Any, address: Any) -> str:
        def nearest(forward: bool) -> Any | None:
            functions = manager.getFunctions(address, forward)
            function = functions.next() if functions.hasNext() else None
            if function is None or function.isExternal():
                return None
            return function

        previous = nearest(False)
        following = nearest(True)

        if previous is None:
            previous_hint = "previous function: none"
        else:
            entry = previous.getEntryPoint()
            distance = address.subtract(entry)
            previous_hint = (
                f"previous function: {previous.getName()}@{self._addr_str(entry)} "
                f"({distance:#x} bytes before)"
            )

        if following is None:
            next_hint = "next function: none"
        else:
            entry = following.getEntryPoint()
            distance = entry.subtract(address)
            next_hint = (
                f"next function: {following.getName()}@{self._addr_str(entry)} "
                f"({distance:#x} bytes after)"
            )

        return f"{previous_hint}; {next_hint}"

    def _resolve_symbol(self, session_id: str, address: int | str, *, name: str | None) -> Any:
        addr = self._coerce_address(session_id, address, "address")
        symbols = list(self._get_program(session_id).getSymbolTable().getSymbols(addr))
        if name is not None:
            for symbol in symbols:
                if symbol.getName(True) == name or symbol.getName() == name:
                    return symbol
            raise GhidraBackendError(f"symbol '{name}' not found at {self._addr_str(addr)}")
        if not symbols:
            raise GhidraBackendError(f"no symbol found at {self._addr_str(addr)}")
        for symbol in symbols:
            if symbol.isPrimary():
                return symbol
        return symbols[0]

    def _resolve_data_type(
        self,
        session_id: str,
        *,
        path: str | None,
        name: str | None,
    ) -> Any:
        dtm = self._get_program(session_id).getDataTypeManager()
        if path:
            normalized_path = path if path.startswith("/") else "/" + path
            data_type = dtm.getDataType(normalized_path)
            if data_type is None and name:
                # Accept a category path plus a type name (e.g.
                # path="/TestCat", name="TestStruct").
                data_type = dtm.getDataType(f"{normalized_path.rstrip('/')}/{name}")
            if data_type is None:
                raise GhidraBackendError(f"type not found: {path}")
            return data_type
        if not name:
            raise GhidraBackendError("path or name is required")
        from java.util import ArrayList

        matches = ArrayList()
        dtm.findDataTypes(name, matches)
        if matches.isEmpty():
            raise GhidraBackendError(f"type not found: {name}")
        if matches.size() > 1:
            raise GhidraBackendError(f"type name is ambiguous: {name}")
        return matches.get(0)

    def _parse_data_type(self, session_id: str, type_text: str) -> Any:
        from ghidra.util.data import DataTypeParser

        dtm = self._get_program(session_id).getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        try:
            return parser.parse(type_text)
        except Exception as exc:
            raise GhidraBackendError(f"failed to parse data type '{type_text}': {exc}") from exc

    def _parse_c_declaration(self, session_id: str, declaration: str) -> Any:
        from ghidra.app.util.cparser.C import CParser

        dtm = self._get_program(session_id).getDataTypeManager()
        try:
            cparser = CParser(dtm)
            c_text = declaration if declaration.endswith(";") else declaration + ";"
            result = cparser.parse(c_text)
        except Exception as exc:
            raise GhidraBackendError(
                f"failed to parse C declaration '{declaration}': {exc}"
            ) from exc
        if result is not None:
            return result
        if cparser.getLastDataType() is not None:
            return cparser.getLastDataType()
        raise GhidraBackendError(f"failed to parse C declaration '{declaration}'")

    @staticmethod
    def _is_full_c_declaration(declaration: str) -> bool:
        normalized = declaration.lstrip()
        return re.match(r"typedef\b", normalized) is not None or "{" in normalized

    def _get_all_data_types(self, session_id: str) -> list[Any]:
        from java.util import ArrayList

        result = ArrayList()
        self._get_program(session_id).getDataTypeManager().getAllDataTypes(result)
        return list(result)

    def _comment_type(self, name: str) -> Any:
        from ghidra.program.model.listing import CommentType

        mapping = {
            "plate": CommentType.PLATE,
            "pre": CommentType.PRE,
            "post": CommentType.POST,
            "eol": CommentType.EOL,
            "repeatable": CommentType.REPEATABLE,
        }
        try:
            return mapping[name.lower()]
        except KeyError as exc:
            raise GhidraBackendError(f"unsupported comment_type: {name}") from exc

    def _resolve_variable(
        self,
        function: Any,
        *,
        name: str | None,
        ordinal: int | None,
        storage: str | None,
    ) -> Any:
        candidates = list(function.getParameters()) + list(function.getLocalVariables())
        matched = []
        for variable in candidates:
            if name is not None and variable.getName() != name:
                continue
            if ordinal is not None and getattr(variable, "getOrdinal", lambda: None)() != ordinal:
                continue
            if storage is not None:
                serialized_storage = None
                with suppress(Exception):
                    serialized_storage = str(variable.getVariableStorage())
                if serialized_storage != storage:
                    continue
            matched.append(variable)
        if not matched:
            raise GhidraBackendError("variable not found")
        if len(matched) > 1:
            raise GhidraBackendError("variable selection is ambiguous")
        return matched[0]

    def _project_folder(self, session_id: str, folder_path: str) -> Any:
        project_data = self._get_record(session_id).project.getProjectData()
        if folder_path in {"", "/"}:
            return project_data.getRootFolder()
        folder = project_data.getFolder(folder_path)
        if folder is None:
            raise GhidraBackendError(f"project folder not found: {folder_path}")
        return folder

    def _project_file(self, session_id: str, path: str) -> Any:
        project_data = self._get_record(session_id).project.getProjectData()
        file = project_data.getFile(path)
        if file is None:
            raise GhidraBackendError(f"project file not found: {path}")
        return file

    def _walk_project_folders(self, folder: Any) -> list[Any]:
        items: list[Any] = []
        for child in folder.getFolders():
            items.append(child)
            items.extend(self._walk_project_folders(child))
        return items

    def _walk_project_files(self, folder: Any) -> list[Any]:
        items = list(folder.getFiles())
        for child in folder.getFolders():
            items.extend(self._walk_project_files(child))
        return items

    def _resolve_register(self, session_id: str, name: str) -> Any:
        if not name:
            raise GhidraBackendError("register is required")
        program = self._get_program(session_id)
        register = program.getRegister(name)
        if register is None:
            register = program.getLanguage().getRegister(name)
        if register is None:
            raise GhidraBackendError(f"unknown register: {name}")
        return register

    def _resolve_namespace(self, session_id: str, path: str | None) -> Any:
        if path in {None, "", "/", "::", "Global"}:
            return None
        symbol_table = self._get_program(session_id).getSymbolTable()
        current = None
        cleaned = path.replace("/", "::").strip(":")
        for part in [item for item in cleaned.split("::") if item]:
            current = symbol_table.getNamespace(part, current)
            if current is None:
                raise GhidraBackendError(f"namespace not found: {path}")
        return current

    def _ref_type(self, name: str) -> Any:
        from ghidra.program.model.symbol import RefType

        candidate = name.upper()
        if not hasattr(RefType, candidate):
            raise GhidraBackendError(f"unsupported reference_type: {name}")
        return getattr(RefType, candidate)

    def _source_type(self, name: str) -> Any:
        from ghidra.program.model.symbol import SourceType

        candidate = name.upper()
        if not hasattr(SourceType, candidate):
            raise GhidraBackendError(f"unsupported source_type: {name}")
        return getattr(SourceType, candidate)

    def _resolve_reference(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str | None,
        operand_index: int | None,
    ) -> Any:
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        references = list(
            self._get_program(session_id).getReferenceManager().getReferencesFrom(from_addr)
        )
        if to_address is not None:
            to_addr = self._coerce_address(session_id, to_address, "to_address")
            references = [
                item
                for item in references
                if self._addr_str(item.getToAddress()) == self._addr_str(to_addr)
            ]
        if operand_index is not None:
            references = [
                item for item in references if int(item.getOperandIndex()) == operand_index
            ]
        if not references:
            raise GhidraBackendError("reference not found")
        if len(references) > 1:
            raise GhidraBackendError("reference selection is ambiguous")
        return references[0]

    def _source_file_from_args(
        self,
        *,
        path: str,
        id_type: str | None,
        identifier_hex: str | None,
    ) -> Any:
        if not path:
            raise GhidraBackendError("path is required")
        from ghidra.program.database.sourcemap import SourceFile, SourceFileIdType

        # Ghidra SourceFile rejects relative paths, so resolve them against the
        # current working directory before handing them over.
        source_path = path if Path(path).is_absolute() else str(Path(path).absolute())
        if id_type is None:
            return SourceFile(source_path)
        candidate = id_type.upper()
        if not hasattr(SourceFileIdType, candidate):
            raise GhidraBackendError(f"unsupported id_type: {id_type}")
        try:
            identifier = None if identifier_hex is None else bytes.fromhex(identifier_hex)
        except ValueError as exc:
            raise GhidraBackendError(f"invalid identifier_hex: {exc}") from exc
        return SourceFile(source_path, getattr(SourceFileIdType, candidate), identifier)

    def _find_source_file(self, manager: Any, path: str) -> Any:
        normalized = path if Path(path).is_absolute() else str(Path(path).absolute())
        for source_file in manager.getAllSourceFiles():
            if source_file.getPath() in {path, normalized}:
                return source_file
        raise GhidraBackendError(f"source file not found: {path}")

    def _clone_parameters(self, function: Any) -> list[Any]:
        from ghidra.program.model.listing import ParameterImpl

        return [ParameterImpl(param, function.getProgram()) for param in function.getParameters()]

    def _parameter_from_spec(
        self,
        session_id: str,
        *,
        name: str,
        data_type: str,
        stack_offset: int | None,
        register: str | None,
        fallback: Any | None = None,
    ) -> Any:
        from ghidra.program.model.listing import ParameterImpl
        from ghidra.program.model.symbol import SourceType

        parsed = self._parse_data_type(session_id, data_type)
        program = self._get_program(session_id)
        if fallback is not None and stack_offset is None and register is None:
            param = ParameterImpl(fallback, program)
            param.setName(name, SourceType.USER_DEFINED)
            param.setDataType(parsed, SourceType.USER_DEFINED)
            return param
        if register is not None:
            return ParameterImpl(
                name,
                parsed,
                self._resolve_register(session_id, register),
                program,
                SourceType.USER_DEFINED,
            )
        if stack_offset is not None:
            return ParameterImpl(
                name,
                parsed,
                int(stack_offset),
                program,
                SourceType.USER_DEFINED,
            )
        return ParameterImpl(name, parsed, program, SourceType.USER_DEFINED)

    def _parameter_index(self, params: list[Any], *, ordinal: int | None, name: str | None) -> int:
        matches = []
        for index, param in enumerate(params):
            if (ordinal is not None and int(param.getOrdinal()) == ordinal) or (
                name is not None and param.getName() == name
            ):
                matches.append(index)
        if not matches:
            raise GhidraBackendError("parameter not found")
        if len(matches) > 1:
            raise GhidraBackendError("parameter selection is ambiguous")
        return matches[0]

    def _write_parameters(self, session_id: str, function: Any, params: list[Any]) -> None:
        def mutate() -> None:
            from ghidra.program.model.listing.Function import FunctionUpdateType
            from ghidra.program.model.symbol import SourceType
            from java.util import ArrayList

            java_params = ArrayList()
            for param in params:
                java_params.add(param)

            function.replaceParameters(
                java_params,
                FunctionUpdateType.CUSTOM_STORAGE
                if function.hasCustomVariableStorage()
                else FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Update parameters {function.getName()}", mutate)

    def _normalize_category_path(self, path: str) -> str:
        """Normalize a user-supplied category path to Ghidra's absolute form.

        Ghidra CategoryPath requires a leading '/', but callers should not
        need to remember that (e.g. "TestCat" -> "/TestCat").
        """
        path = path.strip()
        if path in {"", "/"}:
            return "/"
        return path if path.startswith("/") else "/" + path

    def _resolve_category(self, session_id: str, path: str) -> Any:
        dtm = self._get_program(session_id).getDataTypeManager()
        if path in {"", "/"}:
            return dtm.getRootCategory()
        from ghidra.program.model.data import CategoryPath

        category = dtm.getCategory(CategoryPath(self._normalize_category_path(path)))
        if category is None:
            raise GhidraBackendError(f"category not found: {path}")
        return category

    def _walk_categories(self, category: Any) -> list[Any]:
        items: list[Any] = []
        for child in category.getCategories():
            items.append(child)
            items.extend(self._walk_categories(child))
        return items

    def _require_structure(self, data_type: Any) -> Any:
        if not hasattr(data_type, "replaceAtOffset"):
            raise GhidraBackendError("target type is not a structure")
        return data_type

    def _require_union(self, data_type: Any) -> Any:
        if not hasattr(data_type, "delete") or not hasattr(data_type, "add"):
            raise GhidraBackendError("target type is not a union")
        return data_type

    def _require_enum(self, data_type: Any) -> Any:
        if not hasattr(data_type, "remove") or not hasattr(data_type, "getNames"):
            raise GhidraBackendError("target type is not an enum")
        return data_type

    def _resolve_component(
        self,
        composite: Any,
        *,
        offset: int | None,
        ordinal: int | None,
        field_name: str | None,
    ) -> Any:
        matches = [
            component
            for component in composite.getComponents()
            if (
                (offset is not None and int(component.getOffset()) == offset)
                or (ordinal is not None and int(component.getOrdinal()) == ordinal)
                or (field_name is not None and component.getFieldName() == field_name)
            )
        ]
        if not matches:
            raise GhidraBackendError("component not found")
        if len(matches) > 1:
            raise GhidraBackendError("component selection is ambiguous")
        return matches[0]

    def _find_high_symbol(
        self,
        session_id: str,
        function: Any,
        *,
        name: str,
        ordinal: int | None,
        storage: str | None,
        timeout_secs: int = 30,
        global_only: bool = False,
    ) -> Any:
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        symbols = []
        if not global_only:
            symbols.extend(list(high_function.getLocalSymbolMap().getSymbols()))
        symbols.extend(list(high_function.getGlobalSymbolMap().getSymbols()))

        def _normalize_storage(value: Any) -> str:
            return str(value).lower().replace(" ", "").replace("\t", "")

        matches = []
        for symbol in symbols:
            if symbol is None:
                continue
            if name and symbol.getName() != name:
                continue
            if ordinal is not None and int(symbol.getCategoryIndex()) != ordinal:
                continue
            if storage is not None and _normalize_storage(
                symbol.getStorage()
            ) != _normalize_storage(storage):
                continue
            if global_only and not symbol.isGlobal():
                continue
            matches.append(symbol)
        if not matches:
            if storage is not None:
                candidates = [
                    f"{symbol.getName()} (ordinal={int(symbol.getCategoryIndex())}, "
                    f"storage={symbol.getStorage()})"
                    for symbol in symbols[:10]
                ]
                raise GhidraBackendError(
                    f"no decompiler symbol matches name={name!r} ordinal={ordinal!r} "
                    f"storage={storage!r}; available symbols: {', '.join(candidates)}"
                )
            return None
        if len(matches) > 1:
            raise GhidraBackendError("decompiler symbol selection is ambiguous")
        return matches[0]

    def _update_high_symbol(
        self,
        _session_id: str,
        function: Any,
        high_symbol: Any,
        *,
        name: str | None,
        data_type: Any | None,
    ) -> None:
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        _ = function
        HighFunctionDBUtil.updateDBVariable(high_symbol, name, data_type, SourceType.USER_DEFINED)

    def _find_override_symbol(self, session_id: str, function: Any, callsite: Any) -> Any:
        _ = function
        from ghidra.program.model.pcode import HighFunctionDBUtil

        for symbol in self._get_program(session_id).getSymbolTable().getSymbols(callsite):
            with suppress(Exception):
                if HighFunctionDBUtil.readOverride(symbol) is not None:
                    return symbol
        return None
