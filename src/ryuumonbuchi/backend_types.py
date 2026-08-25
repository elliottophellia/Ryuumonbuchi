"""Backend responsibility mixin: _TypeMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from contextlib import suppress
from typing import Any

from .backend_state import GhidraBackendError


class _TypeMixin:
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
