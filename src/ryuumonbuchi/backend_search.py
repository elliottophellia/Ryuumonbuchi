"""Backend responsibility mixin: _SearchMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from collections.abc import Iterable
from contextlib import suppress
from typing import Any

from .backend_state import GhidraBackendError


class _SearchMixin:
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
