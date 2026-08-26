"""Backend responsibility mixin: _RecordMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from contextlib import suppress
from typing import Any


class _RecordMixin:
    def _analysis_option_record(self, options: Any, name: str) -> dict[str, Any]:
        value = options.getValueAsString(name)
        default = options.getDefaultValue(name)
        current = self._option_object(options, name)
        java_type = None
        if current is not None:
            with suppress(Exception):
                java_type = current.getClass().getName()
            if java_type is None:
                java_type = f"python:{type(current).__name__}"
        return {
            "name": name,
            "value": value,
            "default": self._to_jsonable(default),
            "current": self._to_jsonable(current),
            "java_type": java_type,
        }

    def _function_record(self, function: Any) -> dict[str, Any]:
        return {
            "name": function.getName(),
            "entry_point": self._addr_str(function.getEntryPoint()),
            "body_start": self._addr_str(function.getBody().getMinAddress()),
            "body_end": self._addr_str(function.getBody().getMaxAddress()),
            "signature": function.getPrototypeString(False, True),
            "calling_convention": function.getCallingConventionName(),
            "external": bool(function.isExternal()),
            "thunk": bool(function.isThunk()),
        }

    def _variable_record(self, variable: Any) -> dict[str, Any]:
        storage = None
        with suppress(Exception):
            storage = str(variable.getVariableStorage())
        return {
            "name": variable.getName(),
            "data_type": variable.getDataType().getPathName(),
            "storage": storage,
            "comment": variable.getComment(),
            "first_use_offset": getattr(variable, "getFirstUseOffset", lambda: None)(),
        }

    def _parameter_record(self, parameter: Any) -> dict[str, Any]:
        record = self._variable_record(parameter)
        record["ordinal"] = int(parameter.getOrdinal())
        record["auto_parameter"] = bool(getattr(parameter, "isAutoParameter", lambda: False)())
        return record

    def _symbol_record(self, symbol: Any) -> dict[str, Any] | None:
        if symbol is None:
            return None
        namespace = None
        with suppress(Exception):
            parent = symbol.getParentNamespace()
            namespace = parent.getName(True) if parent is not None else None
        return {
            "id": int(symbol.getID()),
            "name": symbol.getName(True),
            "short_name": symbol.getName(),
            "address": self._addr_str(symbol.getAddress()),
            "symbol_type": str(symbol.getSymbolType()),
            "source_type": str(symbol.getSource()),
            "namespace": namespace,
            "primary": bool(symbol.isPrimary()),
            "external": bool(symbol.isExternal()),
        }

    def _reference_record(self, reference: Any) -> dict[str, Any]:
        return {
            "from": self._addr_str(reference.getFromAddress()),
            "to": self._addr_str(reference.getToAddress()),
            "reference_type": str(reference.getReferenceType()),
            "operand_index": int(reference.getOperandIndex()),
            "primary": bool(reference.isPrimary()),
            "external": bool(reference.isExternalReference()),
        }

    def _data_record(self, data: Any) -> dict[str, Any] | None:
        if data is None:
            return None
        value = None
        with suppress(Exception):
            value = data.getDefaultValueRepresentation()
        return {
            "address": self._addr_str(data.getAddress()),
            "length": int(data.getLength()),
            "data_type": data.getDataType().getPathName(),
            "base_data_type": data.getBaseDataType().getPathName(),
            "value": value,
            "label": data.getLabel(),
            "path_name": data.getPathName(),
        }

    def _data_type_record(self, data_type: Any) -> dict[str, Any]:
        length = None
        with suppress(Exception):
            length = int(data_type.getLength())
        return {
            "name": data_type.getName(),
            "display_name": data_type.getDisplayName(),
            "path": data_type.getPathName(),
            "category": str(data_type.getCategoryPath()),
            "length": length,
            "description": data_type.getDescription(),
            "java_type": data_type.getClass().getName(),
        }

    def _pcode_instruction_record(self, instruction: Any) -> dict[str, Any]:
        return {
            "address": self._addr_str(instruction.getAddress()),
            "instruction": instruction.toString(),
            "ops": [self._pcode_op_record(op) for op in instruction.getPcode()],
        }

    def _pcode_op_record(self, op: Any) -> dict[str, Any]:
        inputs = [self._varnode_record(varnode) for varnode in op.getInputs()]
        output = op.getOutput()
        return {
            "opcode": int(op.getOpcode()),
            "mnemonic": op.getMnemonic(),
            "sequence": str(op.getSeqnum()),
            "inputs": inputs,
            "output": self._varnode_record(output) if output is not None else None,
            "text": str(op),
        }

    def _varnode_record(self, varnode: Any) -> dict[str, Any]:
        return {
            "address": self._addr_str(varnode.getAddress()),
            "size": int(varnode.getSize()),
            "space": varnode.getAddress().getAddressSpace().getName(),
            "constant": bool(varnode.isConstant()),
            "register": bool(varnode.isRegister()),
            "unique": bool(varnode.isUnique()),
        }

    def _code_block_key(self, block: Any) -> tuple[str | None, str | None]:
        return (self._addr_str(block.getMinAddress()), self._addr_str(block.getMaxAddress()))

    def _code_block_record(self, block: Any) -> dict[str, Any]:
        return {
            "start": self._addr_str(block.getMinAddress()),
            "end": self._addr_str(block.getMaxAddress()),
            "flow_type": str(block.getFlowType()),
            "name": str(block.getName()),
        }

    def _bookmark_record(self, bookmark: Any) -> dict[str, Any] | None:
        if bookmark is None:
            return None
        return {
            "address": self._addr_str(bookmark.getAddress()),
            "type": bookmark.getTypeString(),
            "category": bookmark.getCategory(),
            "comment": bookmark.getComment(),
        }

    def _function_tag_record(self, tag: Any) -> dict[str, Any]:
        payload = {"name": tag.getName(), "comment": tag.getComment()}
        with suppress(Exception):
            payload["id"] = int(tag.getId())
        return payload

    def _domain_folder_record(self, folder: Any) -> dict[str, Any]:
        payload = {
            "name": folder.getName(),
            "path": folder.getPathname(),
        }
        with suppress(Exception):
            payload["folder_count"] = len(folder.getFolders())
        with suppress(Exception):
            payload["file_count"] = len(folder.getFiles())
        with suppress(Exception):
            shared = folder.getSharedProjectURL()
            payload["shared_project_url"] = None if shared is None else str(shared)
        return payload

    def _domain_file_record(self, file: Any) -> dict[str, Any]:
        payload = {
            "name": file.getName(),
            "path": file.getPathname(),
            "content_type": file.getContentType(),
        }
        with suppress(Exception):
            payload["file_id"] = str(file.getFileID())
        with suppress(Exception):
            payload["domain_object_class"] = file.getDomainObjectClass().getName()
        with suppress(Exception):
            payload["versioned"] = bool(file.isVersioned())
        with suppress(Exception):
            payload["checked_out"] = bool(file.isCheckedOut())
        with suppress(Exception):
            payload["hijacked"] = bool(file.isHijacked())
        with suppress(Exception):
            payload["read_only"] = bool(file.isReadOnly())
        with suppress(Exception):
            payload["in_use"] = bool(file.isInUse())
        with suppress(Exception):
            payload["shared_project_url"] = (
                None
                if file.getSharedProjectURL(None) is None
                else str(file.getSharedProjectURL(None))
            )
        return payload

    def _code_unit_record(self, code_unit: Any) -> dict[str, Any] | None:
        if code_unit is None:
            return None
        payload = {
            "kind": code_unit.getClass().getSimpleName(),
            "address": self._addr_str(code_unit.getAddress()),
            "min_address": self._addr_str(code_unit.getMinAddress()),
            "max_address": self._addr_str(code_unit.getMaxAddress()),
            "length": int(code_unit.getLength()),
        }
        with suppress(Exception):
            payload["mnemonic"] = code_unit.getMnemonicString()
        with suppress(Exception):
            payload["text"] = code_unit.toString()
        with suppress(Exception):
            payload["bytes"] = bytes(code_unit.getBytes()).hex()
        with suppress(Exception):
            payload["label"] = code_unit.getLabel()
        return payload

    def _namespace_record(self, namespace: Any) -> dict[str, Any] | None:
        if namespace is None:
            return {
                "name": "Global",
                "path": "::",
                "symbol_type": "Global",
            }
        payload = {
            "name": namespace.getName(),
            "path": namespace.getName(True),
        }
        with suppress(Exception):
            payload["symbol_type"] = str(namespace.getSymbol().getSymbolType())
        with suppress(Exception):
            payload["id"] = int(namespace.getID())
        return payload

    def _external_location_record(self, location: Any) -> dict[str, Any] | None:
        if location is None:
            return None
        payload = {"display": str(location)}
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
        with suppress(Exception):
            payload["namespace"] = self._namespace_record(location.getParentNameSpace())
        return payload

    def _equate_record(self, equate: Any) -> dict[str, Any] | None:
        if equate is None:
            return None
        return {
            "name": equate.getName(),
            "display_name": equate.getDisplayName(),
            "value": int(equate.getValue()),
            "display_value": equate.getDisplayValue(),
            "reference_count": int(equate.getReferenceCount()),
            "references": [
                {
                    "address": self._addr_str(ref.getAddress()),
                    "operand_index": int(ref.getOpIndex()),
                    "dynamic_hash": int(ref.getDynamicHashValue()),
                }
                for ref in equate.getReferences()
            ],
        }

    def _source_file_record(self, source_file: Any) -> dict[str, Any]:
        identifier = source_file.getIdentifier()
        return {
            "path": source_file.getPath(),
            "filename": source_file.getFilename(),
            "id_type": source_file.getIdType().name(),
            "identifier_hex": None if identifier is None else bytes(identifier).hex(),
        }

    def _source_map_entry_record(self, entry: Any) -> dict[str, Any]:
        return {
            "source_file": self._source_file_record(entry.getSourceFile()),
            "line_number": int(entry.getLineNumber()),
            "base_address": self._addr_str(entry.getBaseAddress()),
            "length": int(entry.getLength()),
            "range": None
            if entry.getRange() is None
            else {
                "start": self._addr_str(entry.getRange().getMinAddress()),
                "end": self._addr_str(entry.getRange().getMaxAddress()),
            },
        }

    def _relocation_record(self, relocation: Any) -> dict[str, Any]:
        payload = {
            "address": self._addr_str(relocation.getAddress()),
            "status": relocation.getStatus().name(),
            "type": int(relocation.getType()),
            "symbol_name": relocation.getSymbolName(),
            "values": [int(value) for value in relocation.getValues()],
        }
        with suppress(Exception):
            payload["bytes"] = bytes(relocation.getBytes()).hex()
        return payload

    def _category_record(self, category: Any) -> dict[str, Any]:
        return {
            "name": category.getName(),
            "path": str(category.getCategoryPath()),
            "subcategory_count": len(category.getCategories()),
            "type_count": len(category.getDataTypes()),
        }

    def _source_archive_record(self, archive: Any) -> dict[str, Any]:
        payload = {
            "name": archive.getName(),
            "source_archive_id": int(archive.getSourceArchiveID().getValue()),
        }
        with suppress(Exception):
            payload["path"] = archive.getPath()
        return payload

    def _component_record(self, component: Any) -> dict[str, Any]:
        return {
            "ordinal": int(component.getOrdinal()),
            "offset": int(component.getOffset()),
            "length": int(component.getLength()),
            "field_name": component.getFieldName(),
            "comment": component.getComment(),
            "data_type": component.getDataType().getPathName(),
        }

    def _components_record(self, composite: Any) -> list[dict[str, Any]]:
        return [self._component_record(component) for component in composite.getComponents()]

    def _high_symbol_record(self, high_symbol: Any) -> dict[str, Any]:
        payload = {
            "name": high_symbol.getName(),
            "data_type": high_symbol.getDataType().getPathName(),
            "category_index": int(high_symbol.getCategoryIndex()),
            "is_parameter": bool(high_symbol.isParameter()),
            "is_global": bool(high_symbol.isGlobal()),
            "storage": str(high_symbol.getStorage()),
            "pc_address": self._addr_str(high_symbol.getPCAddress()),
        }
        with suppress(Exception):
            payload["symbol"] = self._symbol_record(high_symbol.getSymbol())
        return payload

    def _clang_node_record(self, node: Any) -> dict[str, Any] | None:
        if node is None:
            return None
        payload = {
            "type": node.getClass().getSimpleName(),
            "text": str(node),
            "min_address": self._addr_str(node.getMinAddress()),
            "max_address": self._addr_str(node.getMaxAddress()),
            "child_count": int(node.numChildren()),
        }
        if node.numChildren() > 0:
            payload["children"] = [
                self._clang_node_record(node.Child(index))
                for index in range(int(node.numChildren()))
            ]
        return payload
