"""Backend responsibility mixin: _ListingMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import base64
from typing import Any

from .state import MAX_MEMORY_READ_BYTES, GhidraBackendError


class _ListingMixin:
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
