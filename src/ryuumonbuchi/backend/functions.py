"""Backend responsibility mixin: _FunctionMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .state import GhidraBackendError


class _FunctionMixin:
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
