"""Backend responsibility mixin: _SymbolMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

from contextlib import suppress
from typing import Any

from .state import GhidraBackendError


class _SymbolMixin:
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
