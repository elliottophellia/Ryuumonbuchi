"""Backend responsibility mixin: _BackendCore."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import base64
import binascii
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from typing import Any
from uuid import uuid4

from .backend_state import BackendConfig, GhidraBackendError, SessionRecord, TaskRecord


class _BackendCore:
    def __init__(
        self,
        pyghidra_module: Any,
        config: BackendConfig,
    ) -> None:
        self._pyghidra = pyghidra_module
        self._config = config
        self._install_dir = config.install_dir
        self._deterministic = config.deterministic
        self._sessions: dict[str, SessionRecord] = {}
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self._startup_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ryuumonbuchi")
        self._started = False
        self._launcher: Any = None
        self._generation = str(uuid4())

    def ping(self) -> dict[str, str]:
        return {"status": "ok", "message": "pong"}

    def shutdown(self) -> None:
        task_ids = list(self._tasks)
        for task_id in task_ids:
            with suppress(Exception):
                self.task_cancel(task_id)
        session_ids = list(self._sessions)
        for session_id in session_ids:
            with suppress(Exception):
                self.session_close(session_id)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _get_record(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise GhidraBackendError(f"unknown session_id: {session_id}")
        return record

    def _get_program(self, session_id: str) -> Any:
        return self._get_record(session_id).program

    def _require_writable_session(self, session_id: str) -> SessionRecord:
        record = self._get_record(session_id)
        if record.read_only:
            raise GhidraBackendError(f"session {session_id} is read-only")
        return record

    def _with_write(self, session_id: str, description: str, func: Callable[[], Any]) -> Any:
        record = self._require_writable_session(session_id)
        if record.active_transaction_id is not None:
            return func()
        tx_id = int(record.program.startTransaction(description))
        committed = False
        try:
            result = func()
            committed = True
            return result
        finally:
            record.program.endTransaction(tx_id, committed)

    def _validate_offset_limit(self, offset: int, limit: int) -> None:
        if offset < 0:
            raise GhidraBackendError("offset must be >= 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")

    def _coerce_address(self, session_id: str, value: int | str | Any, arg_name: str) -> Any:
        program = self._get_program(session_id)
        factory = program.getAddressFactory()
        if value is None:
            raise GhidraBackendError(f"{arg_name} is required")
        if hasattr(value, "getAddressSpace") and hasattr(value, "getOffset"):
            return value
        if isinstance(value, int):
            return factory.getDefaultAddressSpace().getAddress(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise GhidraBackendError(f"{arg_name} is required")
            with suppress(Exception):
                addr = factory.getAddress(text)
                if addr is not None:
                    return addr
            with suppress(Exception):
                return factory.getDefaultAddressSpace().getAddress(int(text, 0))
        raise GhidraBackendError(f"invalid {arg_name}: {value!r}")

    def _addr_str(self, address: Any) -> str | None:
        if address is None:
            return None
        return str(address)

    def _function_sort_key(self, function: Any) -> tuple[int, str]:
        return (int(function.getEntryPoint().getOffset()), function.getName())

    def _coerce_address_range(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        arg_name: str,
    ) -> tuple[Any, Any, Any]:
        if length is not None and length <= 0:
            raise GhidraBackendError("length must be > 0")
        start_addr = self._coerce_address(session_id, start, arg_name)
        if end is not None:
            end_addr = self._coerce_address(session_id, end, "end")
        elif length is not None:
            end_addr = start_addr.add(int(length) - 1)
        else:
            end_addr = start_addr
        from ghidra.program.model.address import AddressSet

        return start_addr, end_addr, AddressSet(start_addr, end_addr)

    def _optional_address_range(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        length: int | None = None,
        arg_name: str,
    ) -> tuple[Any | None, Any | None, Any | None]:
        if start is None:
            if end is not None or length is not None:
                raise GhidraBackendError(f"{arg_name} is required when end or length is provided")
            return None, None, None
        return self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name=arg_name,
        )

    def _decode_payload(self, *, data_base64: str | None, data_hex: str | None) -> bytes:
        if bool(data_base64) == bool(data_hex):
            raise GhidraBackendError("exactly one of data_base64 or data_hex is required")
        if data_base64:
            try:
                return base64.b64decode(data_base64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise GhidraBackendError(f"invalid base64 payload: {exc}") from exc
        try:
            return bytes.fromhex(data_hex or "")
        except ValueError as exc:
            raise GhidraBackendError(f"invalid hex payload: {exc}") from exc

    def _to_jsonable(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")
        if isinstance(value, dict):
            return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._to_jsonable(item) for item in value]
        if hasattr(value, "items"):
            with suppress(Exception):
                return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if hasattr(value, "getEntryPoint") and hasattr(value, "getProgram"):
            return self._function_record(value)
        if hasattr(value, "getPathName") and hasattr(value, "getDisplayName"):
            return self._data_type_record(value)
        if hasattr(value, "getSymbolType") and hasattr(value, "getAddress"):
            return self._symbol_record(value)
        if hasattr(value, "getAddressSpace") and hasattr(value, "getOffset"):
            return self._addr_str(value)
        if hasattr(value, "getBytes") and hasattr(value, "toString"):
            with suppress(Exception):
                return str(value)
        if hasattr(value, "toArray"):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value.toArray()]
        if hasattr(value, "iterator"):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value]
        return str(value)
