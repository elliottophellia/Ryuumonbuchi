"""Backend responsibility mixin: _AnalysisMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import Future
from contextlib import suppress
from typing import Any
from uuid import uuid4

from .backend_state import DEFAULT_ANALYSIS_TIMEOUT, GhidraBackendError, SessionRecord, TaskRecord


class _AnalysisMixin:
    def analysis_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        return {
            "session_id": session_id,
            "status": record.last_analysis_status,
            "last_analysis_started_at": record.last_analysis_started_at,
            "last_analysis_completed_at": record.last_analysis_completed_at,
            "last_analysis_task_id": record.last_analysis_task_id,
            "last_analysis_error": record.last_analysis_error,
            "has_log": record.last_analysis_log is not None,
        }

    def analysis_update(self, session_id: str) -> dict[str, Any]:
        return self.task_analysis_update(session_id)

    def analysis_update_and_wait(self, session_id: str) -> dict[str, Any]:
        record = self._begin_analysis(session_id)
        try:
            monitor = self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT)
        except Exception as exc:
            self._fail_analysis_start(record, exc)
            raise GhidraBackendError(f"failed to create analysis monitor: {exc}") from exc
        try:
            log = self._analyze_program(record.program, monitor)
        except Exception as exc:
            record.last_analysis_status = "failed"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = str(exc)
            raise GhidraBackendError(f"analysis failed: {exc}") from exc

        self._finalize_open_program(record.program, record.project)
        record.last_analysis_log = log or ""
        record.last_analysis_status = "completed"
        record.last_analysis_completed_at = time.time()
        return {
            "session_id": session_id,
            "status": record.last_analysis_status,
            "log": record.last_analysis_log,
        }

    def analysis_options_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._analysis_options(session_id)
        names = sorted(str(name) for name in options.getOptionNames())
        if query:
            needle = query.lower()
            names = [name for name in names if needle in name.lower()]
        items = [
            self._analysis_option_record(options, name) for name in names[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def analysis_options_get(self, session_id: str, name: str) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        options = self._analysis_options(session_id)
        self._require_option(options, name)
        return {"session_id": session_id, **self._analysis_option_record(options, name)}

    def analysis_options_set(self, session_id: str, name: str, value: Any) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        options = self._analysis_options(session_id)
        self._require_option(options, name)

        def mutate() -> None:
            current = self._option_object(options, name)
            if isinstance(value, bool):
                options.setBoolean(name, value)
            elif isinstance(value, int) and not isinstance(value, bool):
                if current is not None and current.__class__.__name__.lower().endswith("long"):
                    options.setLong(name, value)
                else:
                    options.setInt(name, value)
            elif isinstance(value, float):
                options.setDouble(name, value)
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if current is not None and current.__class__.__name__.lower().endswith("boolean"):
                    options.setBoolean(name, lowered in {"1", "true", "yes", "on"})
                elif current is not None and current.__class__.__name__.lower().endswith("integer"):
                    options.setInt(name, int(value, 0))
                elif current is not None and current.__class__.__name__.lower().endswith("long"):
                    options.setLong(name, int(value, 0))
                elif current is not None and current.__class__.__name__.lower().endswith("double"):
                    options.setDouble(name, float(value))
                elif current is not None and current.__class__.__name__.lower().endswith("float"):
                    options.setFloat(name, float(value))
                else:
                    options.setString(name, value)
            else:
                raise GhidraBackendError("unsupported option value type")

        self._with_write(session_id, f"Set analysis option {name}", mutate)
        return self.analysis_options_get(session_id, name)

    def decomp_function(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return self._decompile_function(session_id, function, timeout_secs=timeout_secs)

    def pcode_function(
        self,
        session_id: str,
        function_start: int | str,
        *,
        limit: int = 200,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        function = self._resolve_function(session_id, function_start)
        listing = self._get_program(session_id).getListing()
        instructions = listing.getInstructions(function.getBody(), True)
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            items.append(self._pcode_instruction_record(instruction))
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def pcode_op_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        instruction = self._get_program(session_id).getListing().getInstructionAt(addr)
        if instruction is None:
            raise GhidraBackendError(f"no instruction at {self._addr_str(addr)}")
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "instruction": instruction.toString(),
            "ops": [self._pcode_op_record(op) for op in instruction.getPcode()],
        }

    def function_basic_blocks(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        blocks = self._function_code_blocks(function)
        items = [self._code_block_record(block) for block in blocks]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def cfg_edges(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        blocks = self._function_code_blocks(function)
        block_keys = {self._code_block_key(block) for block in blocks}
        edges: list[dict[str, Any]] = []
        monitor = self._pyghidra.task_monitor()
        for block in blocks:
            destinations = block.getDestinations(monitor)
            while destinations.hasNext():
                ref = destinations.next()
                destination = ref.getDestinationBlock()
                if destination is None or self._code_block_key(destination) not in block_keys:
                    continue
                edges.append(
                    {
                        "source": self._code_block_record(block),
                        "target": self._code_block_record(destination),
                        "flow_type": str(ref.getFlowType()),
                        "referent": self._addr_str(ref.getReferent()),
                        "reference": self._addr_str(ref.getReference()),
                    }
                )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(edges),
            "items": edges,
        }

    def callgraph_paths(
        self,
        session_id: str,
        source_function: int | str,
        target_function: int | str,
        *,
        max_depth: int = 4,
        limit: int = 10,
    ) -> dict[str, Any]:
        if max_depth <= 0:
            raise GhidraBackendError("max_depth must be > 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        source = self._resolve_function(session_id, source_function)
        target = self._resolve_function(session_id, target_function)
        target_entry = self._addr_str(target.getEntryPoint())
        queue: deque[list[Any]] = deque([[source]])
        paths: list[list[dict[str, Any]]] = []
        while queue and len(paths) < limit:
            path = queue.popleft()
            current = path[-1]
            if self._addr_str(current.getEntryPoint()) == target_entry:
                paths.append([self._function_record(func) for func in path])
                continue
            if len(path) - 1 >= max_depth:
                continue
            callees = sorted(
                current.getCalledFunctions(self._pyghidra.task_monitor()),
                key=self._function_sort_key,
            )
            seen_in_path = {self._addr_str(func.getEntryPoint()) for func in path}
            for callee in callees:
                callee_entry = self._addr_str(callee.getEntryPoint())
                if callee_entry in seen_in_path:
                    continue
                queue.append([*path, callee])
        return {
            "session_id": session_id,
            "source": self._function_record(source),
            "target": self._function_record(target),
            "max_depth": max_depth,
            "count": len(paths),
            "items": paths,
        }

    def analysis_analyzers_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._analysis_options(session_id)
        names = []
        for name in sorted(str(item) for item in options.getOptionNames()):
            current = self._option_object(options, name)
            if current is None:
                continue
            if current.__class__.__name__.lower().endswith("boolean"):
                names.append(name)
        if query:
            needle = query.lower()
            names = [name for name in names if needle in name.lower()]
        items = [
            self._analysis_option_record(options, name) for name in names[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def analysis_analyzers_set(
        self, session_id: str, *, name: str, enabled: bool
    ) -> dict[str, Any]:
        return self.analysis_options_set(session_id, name, bool(enabled))

    def analysis_clear_cache(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        cleared = False
        if record.decompiler is not None:
            with suppress(Exception):
                record.decompiler.closeProgram()
                record.decompiler.dispose()
            record.decompiler = None
            cleared = True
        return {"session_id": session_id, "decompiler_cleared": cleared}

    def decomp_tokens(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        payload = self._decompile_payload(session_id, function, results)
        markup = results.getCCodeMarkup()
        payload["tokens"] = self._clang_node_record(markup)
        return payload

    def decomp_ast(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        payload = self._decompile_payload(session_id, function, results)
        payload["ast"] = self._clang_node_record(results.getCCodeMarkup())
        return payload

    def pcode_block(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        block = self._code_block_containing(session_id, addr)
        instructions = self._get_program(session_id).getListing().getInstructions(block, True)
        items = [self._pcode_instruction_record(instruction) for instruction in instructions]
        return {
            "session_id": session_id,
            "block": self._code_block_record(block),
            "count": len(items),
            "items": items,
        }

    def pcode_varnode_uses(
        self,
        session_id: str,
        *,
        function_start: int | str,
        varnode: str | None = None,
        address: int | str | None = None,
        space: str | None = None,
        size: int | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        items: list[dict[str, Any]] = []
        for op in self._collect_high_pcode_ops(high_function):
            output = op.getOutput()
            if output is not None and self._varnode_matches(
                session_id, output, query=varnode, address=address, space=space, size=size
            ):
                items.append(
                    {
                        "access": "write",
                        "op": self._pcode_op_record(op),
                    }
                )
            items.extend(
                {
                    "access": "read",
                    "op": self._pcode_op_record(op),
                }
                for input_varnode in op.getInputs()
                if self._varnode_matches(
                    session_id,
                    input_varnode,
                    query=varnode,
                    address=address,
                    space=space,
                    size=size,
                )
            )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def task_analysis_update(self, session_id: str) -> dict[str, Any]:
        record = self._begin_analysis(session_id)
        try:
            monitor = self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT)
        except Exception as exc:
            self._fail_analysis_start(record, exc)
            raise GhidraBackendError(f"failed to create analysis monitor: {exc}") from exc

        def run() -> dict[str, Any]:
            try:
                log = self._analyze_program(record.program, monitor)
            except Exception as exc:
                record.last_analysis_status = "failed"
                record.last_analysis_completed_at = time.time()
                record.last_analysis_error = str(exc)
                raise GhidraBackendError(f"analysis failed: {exc}") from exc
            self._finalize_open_program(record.program, record.project)
            record.last_analysis_status = "completed"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_log = log or ""
            return {
                "session_id": session_id,
                "status": record.last_analysis_status,
                "log": record.last_analysis_log,
            }

        try:
            payload = self._submit_task(
                kind="analysis.update_and_wait",
                session_id=session_id,
                func=run,
                cancel_hook=lambda: monitor.cancel(),
            )
        except Exception as exc:
            self._fail_analysis_start(record, exc)
            raise GhidraBackendError(f"failed to submit analysis task: {exc}") from exc
        record.last_analysis_task_id = payload["task_id"]
        task = self._get_task(payload["task_id"])
        task.future.add_done_callback(
            lambda future: self._finalize_cancelled_analysis(record, payload["task_id"], future)
        )
        return payload

    def task_status(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        status = self._task_state(task)
        error: str | None = None
        if status == "failed":
            exc = task.future.exception()
            if exc is not None:
                error = str(exc)
        return {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": status,
            "cancel_requested": task.cancel_requested,
            "cancel_supported": task.cancel_hook is not None,
            "result_ready": status in {"completed", "failed", "cancelled"},
            "error": error,
            "created_at": task.created_at,
        }

    def task_result(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        status = self._task_state(task)
        if status not in {"completed", "failed", "cancelled"}:
            raise GhidraBackendError(f"task {task_id} is not in a terminal state (status={status})")
        payload = {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": status,
        }
        if task.future.cancelled():
            return payload
        exc = task.future.exception()
        if exc is not None:
            payload["error"] = str(exc)
            return payload
        payload["result"] = task.future.result()
        return payload

    def task_cancel(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        task.cancel_requested = True
        cancelled = task.future.cancel()
        if task.cancel_hook is not None:
            with suppress(Exception):
                task.cancel_hook()
        return {
            "task_id": task_id,
            "cancel_requested": True,
            "cancelled": cancelled,
            "status": self._task_state(task),
        }

    def decomp_high_function_summary(
        self,
        session_id: str,
        *,
        function_start: int | str,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        local_symbols = [
            self._high_symbol_record(item)
            for item in high_function.getLocalSymbolMap().getSymbols()
        ]
        global_symbols = [
            self._high_symbol_record(item)
            for item in high_function.getGlobalSymbolMap().getSymbols()
        ]
        jump_tables = [str(item) for item in high_function.getJumpTables()]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "local_symbol_count": len(local_symbols),
            "global_symbol_count": len(global_symbols),
            "block_count": len(list(high_function.getBasicBlocks())),
            "jump_table_count": len(jump_tables),
            "local_symbols": local_symbols,
            "global_symbols": global_symbols,
            "jump_tables": jump_tables,
        }

    def decomp_writeback_params(
        self,
        session_id: str,
        *,
        function_start: int | str,
        use_data_types: bool = True,
        commit_return: bool = False,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.pcode import HighFunctionDBUtil
            from ghidra.program.model.pcode.HighFunctionDBUtil import ReturnCommitOption
            from ghidra.program.model.symbol import SourceType

            high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
            HighFunctionDBUtil.commitParamsToDatabase(
                high_function,
                bool(use_data_types),
                ReturnCommitOption.COMMIT if commit_return else ReturnCommitOption.NO_COMMIT,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Writeback params {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def decomp_writeback_locals(
        self,
        session_id: str,
        *,
        function_start: int | str,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.pcode import HighFunctionDBUtil
            from ghidra.program.model.symbol import SourceType

            high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
            HighFunctionDBUtil.commitLocalNamesToDatabase(high_function, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Writeback locals {function.getName()}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def decomp_override_get(
        self,
        session_id: str,
        *,
        function_start: int | str,
        callsite: int | str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callsite_addr = self._coerce_address(session_id, callsite, "callsite")
        symbol = self._find_override_symbol(session_id, function, callsite_addr)
        if symbol is None:
            return {
                "session_id": session_id,
                "function": self._function_record(function),
                "callsite": self._addr_str(callsite_addr),
                "override": None,
            }
        from ghidra.program.model.pcode import HighFunctionDBUtil

        override = HighFunctionDBUtil.readOverride(symbol)
        data_type = None if override is None else override.getDataType()
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "callsite": self._addr_str(callsite_addr),
            "override": None
            if data_type is None
            else {
                "symbol": self._symbol_record(symbol),
                "signature": data_type.getPrototypeString(),
                "type": self._data_type_record(data_type),
            },
        }

    def decomp_override_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        callsite: int | str,
        signature: str,
    ) -> dict[str, Any]:
        if not signature:
            raise GhidraBackendError("signature is required")
        function = self._resolve_function(session_id, function_start)
        callsite_addr = self._coerce_address(session_id, callsite, "callsite")

        def mutate() -> None:
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.pcode import HighFunctionDBUtil

            definition = CParserUtils.parseSignature(
                None, self._get_program(session_id), signature, False
            )
            if definition is None:
                raise GhidraBackendError("failed to parse signature")
            existing = self._find_override_symbol(session_id, function, callsite_addr)
            if existing is not None:
                existing.delete()
            HighFunctionDBUtil.writeOverride(function, callsite_addr, definition)

        self._with_write(session_id, f"Set override {function.getName()}", mutate)
        return self.decomp_override_get(
            session_id, function_start=function.getEntryPoint(), callsite=callsite_addr
        )

    def decomp_trace_type_forward(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        return self._decomp_trace_type(
            session_id,
            function_start=function_start,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
            direction="forward",
        )

    def decomp_trace_type_backward(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        return self._decomp_trace_type(
            session_id,
            function_start=function_start,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
            direction="backward",
        )

    def decomp_global_rename(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        new_name: str,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=None,
            storage=storage,
            timeout_secs=timeout_secs,
            global_only=True,
        )
        if high_symbol is None:
            raise GhidraBackendError("global symbol not found")

        def mutate() -> None:
            self._update_high_symbol(
                session_id, function, high_symbol, name=new_name, data_type=None
            )

        self._with_write(session_id, f"Rename global {name}", mutate)
        return self.decomp_high_function_summary(
            session_id, function_start=function.getEntryPoint(), timeout_secs=timeout_secs
        )

    def decomp_global_retype(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=None,
            storage=storage,
            timeout_secs=timeout_secs,
            global_only=True,
        )
        if high_symbol is None:
            raise GhidraBackendError("global symbol not found")
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            self._update_high_symbol(session_id, function, high_symbol, name=None, data_type=parsed)

        self._with_write(session_id, f"Retype global {name}", mutate)
        return self.decomp_high_function_summary(
            session_id, function_start=function.getEntryPoint(), timeout_secs=timeout_secs
        )

    def _get_task(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise GhidraBackendError(f"unknown task_id: {task_id}")
        return task

    def _task_state(self, task: TaskRecord) -> str:
        future = task.future
        if future.cancelled():
            return "cancelled"
        if future.done():
            return "failed" if future.exception() is not None else "completed"
        if future.running():
            return "cancelling" if task.cancel_requested else "running"
        return "queued"

    def _submit_task(
        self,
        *,
        kind: str,
        session_id: str | None,
        func: Callable[[], Any],
        cancel_hook: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        task_id = uuid4().hex
        future = self._executor.submit(func)
        record = TaskRecord(
            task_id=task_id,
            kind=kind,
            future=future,
            session_id=session_id,
            cancel_hook=cancel_hook,
        )
        with self._lock:
            self._tasks[task_id] = record
        return {
            "task_id": task_id,
            "kind": kind,
            "session_id": session_id,
            "status": self._task_state(record),
        }

    def _begin_analysis(self, session_id: str) -> SessionRecord:
        """Mark analysis as running, rejecting concurrent analysis on the same session.

        Ghidra program transactions are not thread-safe, so two overlapping
        analysis passes on one program (e.g. analysis.update and
        analysis.update_and_wait) corrupt each other.
        """
        record = self._get_record(session_id)
        with self._lock:
            if record.last_analysis_status == "running":
                raise GhidraBackendError(
                    f"analysis is already running for session {session_id}; "
                    "wait for it to complete before starting another"
                )
            record.last_analysis_status = "running"
            record.last_analysis_started_at = time.time()
            record.last_analysis_completed_at = None
            record.last_analysis_error = None
            record.last_analysis_task_id = None
        return record

    def _fail_analysis_start(self, record: SessionRecord, exc: Exception) -> None:
        with self._lock:
            record.last_analysis_status = "failed"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = str(exc)

    def _finalize_cancelled_analysis(
        self,
        record: SessionRecord,
        task_id: str,
        future: Future[Any],
    ) -> None:
        if not future.cancelled():
            return
        with self._lock:
            if record.last_analysis_task_id != task_id or record.last_analysis_status != "running":
                return
            record.last_analysis_status = "cancelled"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = None

    def _analyze_program(self, program: Any, monitor: Any) -> str:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities

        tx_id = int(program.startTransaction("Analysis"))
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
            manager.startAnalysis(monitor)
            GhidraProgramUtilities.markProgramAnalyzed(program)
            return str(manager.getMessageLog().toString())
        finally:
            program.endTransaction(tx_id, True)

    def _analysis_options(self, session_id: str) -> Any:
        return self._pyghidra.analysis_properties(self._get_program(session_id))

    def _option_object(self, options: Any, name: str) -> Any:
        return options.getObject(name, None)

    def _require_option(self, options: Any, name: str) -> None:
        names = {str(option_name) for option_name in options.getOptionNames()}
        if name not in names:
            raise GhidraBackendError(f"unknown analysis option: {name}")

    def _decompile_function(
        self, session_id: str, function: Any, *, timeout_secs: int
    ) -> dict[str, Any]:
        if timeout_secs <= 0:
            raise GhidraBackendError("timeout_secs must be > 0")
        decompiler = self._get_decompiler(session_id)
        results = decompiler.decompileFunction(
            function, timeout_secs, self._pyghidra.task_monitor(timeout_secs)
        )
        payload = {
            "session_id": session_id,
            "function": self._function_record(function),
            "decompile_completed": bool(results.decompileCompleted()),
            "timed_out": bool(results.isTimedOut()),
            "cancelled": bool(results.isCancelled()),
            "error_message": results.getErrorMessage(),
        }
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            payload["c"] = decompiled.getC()
            payload["signature"] = decompiled.getSignature()
        return payload

    def _get_decompiler(self, session_id: str) -> Any:
        record = self._get_record(session_id)
        if record.decompiler is None:
            from ghidra.app.decompiler import DecompInterface

            decompiler = DecompInterface()
            decompiler.toggleCCode(True)
            decompiler.toggleSyntaxTree(True)
            decompiler.setSimplificationStyle("decompile")
            if not decompiler.openProgram(record.program):
                decompiler.dispose()
                raise GhidraBackendError("failed to open decompiler for program")
            record.decompiler = decompiler
        return record.decompiler

    def _function_code_blocks(self, function: Any) -> list[Any]:
        from ghidra.program.model.block import BasicBlockModel

        model = BasicBlockModel(function.getProgram())
        monitor = self._pyghidra.task_monitor()
        seen: set[tuple[str | None, str | None]] = set()
        items: list[Any] = []
        for block in model.getCodeBlocksContaining(function.getBody(), monitor):
            key = self._code_block_key(block)
            if key in seen:
                continue
            seen.add(key)
            items.append(block)
        return items

    def _code_block_containing(self, session_id: str, address: Any) -> Any:
        from ghidra.program.model.block import BasicBlockModel

        model = BasicBlockModel(self._get_program(session_id))
        monitor = self._pyghidra.task_monitor()
        blocks = model.getCodeBlocksContaining(address, monitor)
        if not blocks:
            raise GhidraBackendError(f"no basic block found at {self._addr_str(address)}")
        return blocks[0]

    def _decomp_trace_type(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None,
        storage: str | None,
        timeout_secs: int,
        direction: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
        )
        if high_symbol is None or high_symbol.getHighVariable() is None:
            raise GhidraBackendError("decompiler symbol not found")
        representative = high_symbol.getHighVariable().getRepresentative()
        from ghidra.app.decompiler.component import DecompilerUtils

        ops = (
            DecompilerUtils.getForwardSliceToPCodeOps(representative)
            if direction == "forward"
            else DecompilerUtils.getBackwardSliceToPCodeOps(representative)
        )
        op_list = list(ops)
        return {
            "session_id": session_id,
            "direction": direction,
            "function": self._function_record(function),
            "symbol": self._high_symbol_record(high_symbol),
            "count": len(op_list),
            "items": [self._pcode_op_record(op) for op in op_list],
        }

    def _decompile_results(self, session_id: str, function: Any, *, timeout_secs: int) -> Any:
        if timeout_secs <= 0:
            raise GhidraBackendError("timeout_secs must be > 0")
        return self._get_decompiler(session_id).decompileFunction(
            function,
            timeout_secs,
            self._pyghidra.task_monitor(timeout_secs),
        )

    def _decompile_payload(self, session_id: str, function: Any, results: Any) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "function": self._function_record(function),
            "decompile_completed": bool(results.decompileCompleted()),
            "timed_out": bool(results.isTimedOut()),
            "cancelled": bool(results.isCancelled()),
            "error_message": results.getErrorMessage(),
        }
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            payload["c"] = decompiled.getC()
            payload["signature"] = decompiled.getSignature()
        return payload

    def _high_function(self, session_id: str, function: Any, *, timeout_secs: int) -> Any:
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        high_function = results.getHighFunction()
        if high_function is None:
            raise GhidraBackendError(
                results.getErrorMessage() or "failed to obtain high function from decompiler"
            )
        return high_function

    def _collect_high_pcode_ops(self, high_function: Any) -> list[Any]:
        return [op for block in high_function.getBasicBlocks() for op in block.getIterator()]

    def _varnode_matches(
        self,
        session_id: str,
        candidate: Any,
        *,
        query: str | None,
        address: int | str | None,
        space: str | None,
        size: int | None,
    ) -> bool:
        if candidate is None:
            return False
        record = self._varnode_record(candidate)
        if query is not None:
            needle = query.lower()
            values = [
                str(record.get("address", "")).lower(),
                str(record.get("space", "")).lower(),
                str(record.get("size", "")).lower(),
            ]
            if not any(needle in value for value in values):
                return False
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            if record["address"] != self._addr_str(addr):
                return False
        if space is not None and record["space"] != space:
            return False
        return not (size is not None and record["size"] != size)
