"""Backend responsibility mixin: _ReferenceMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from contextlib import suppress
from typing import Any

from .state import GhidraBackendError


class _ReferenceMixin:
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
