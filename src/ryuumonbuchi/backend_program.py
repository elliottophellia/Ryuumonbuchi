"""Backend responsibility mixin: _ProgramMixin."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportPrivateUsage=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false, reportAssignmentType=false, reportReturnType=false, reportIncompatibleMethodOverride=false, reportMissingTypeArgument=false, reportMissingTypeStubs=false, reportUnnecessaryComparison=false, reportUndefinedVariable=false, reportPossiblyUnboundVariable=false, reportOptionalMemberAccess=false, reportUnusedClass=false
from __future__ import annotations

import base64
import binascii
import io
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Iterable
from contextlib import redirect_stderr, redirect_stdout, suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from .backend_state import DEFAULT_ANALYSIS_TIMEOUT, GhidraBackendError, SessionRecord


class _ProgramMixin:
    def ghidra_info(self) -> dict[str, Any]:
        self._ensure_started()
        from ghidra.framework import Application

        version = None
        with suppress(Exception):
            version = Application.getApplicationVersion()

        return {
            "status": "ok",
            "install_dir": self._install_dir,
            "ghidra_version": version,
            "pyghidra_version": getattr(self._pyghidra, "__version__", None),
            "deterministic": self._deterministic,
            "jvm_started": bool(self._pyghidra.started()),
        }

    def session_open(
        self,
        path: str,
        *,
        update_analysis: bool = True,
        read_only: bool = True,
        project_location: str | None = None,
        project_name: str | None = None,
        program_name: str | None = None,
        language: str | None = None,
        compiler: str | None = None,
        loader: str | None = None,
    ) -> dict[str, Any]:
        self._ensure_started()
        if not path:
            raise GhidraBackendError("path is required")
        binary_path = Path(path)
        if not binary_path.exists():
            raise GhidraBackendError(f"path does not exist: {path}")

        project_root, effective_project_name, managed_project = self._allocate_project(
            binary_path.name,
            project_location=project_location,
            project_name=project_name,
        )
        project = self._open_or_create_project(project_root, effective_project_name)
        effective_program_name = program_name or binary_path.name
        program = self._import_or_open_program(
            project,
            str(binary_path),
            effective_program_name,
            language=language,
            compiler=compiler,
            loader=loader,
        )
        self._finalize_open_program(program, project)

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=project_root,
            project_name=effective_project_name,
            program_name=effective_program_name,
            program_path=f"/{effective_program_name}",
            source_path=str(binary_path),
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=project_root if managed_project else None,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

        return self.binary_summary(session_id)

    def session_open_bytes(
        self,
        data_base64: str,
        *,
        filename: str = "session.bin",
        update_analysis: bool = True,
        read_only: bool = True,
        project_location: str | None = None,
        project_name: str | None = None,
        program_name: str | None = None,
        language: str | None = None,
        compiler: str | None = None,
        loader: str | None = None,
    ) -> dict[str, Any]:
        self._ensure_started()
        if not self._config.allow_import_bytes:
            raise GhidraBackendError(
                "program.open_bytes is disabled; set RYUUMONBUCHI_ALLOW_IMPORT_BYTES=1 to enable"
            )
        if not data_base64:
            raise GhidraBackendError("data_base64 is required")
        try:
            raw_bytes = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise GhidraBackendError(f"invalid base64 data: {exc}") from exc
        if len(raw_bytes) > self._config.max_import_bytes:
            raise GhidraBackendError(
                f"import payload {len(raw_bytes)} bytes exceeds max_import_bytes "
                f"{self._config.max_import_bytes}"
            )

        effective_program_name = program_name or filename or "session.bin"
        project_root, effective_project_name, managed_project = self._allocate_project(
            effective_program_name,
            project_location=project_location,
            project_name=project_name,
        )
        project = self._open_or_create_project(project_root, effective_project_name)

        temp_source_path: str | None = None
        consumer = None
        try:
            program, consumer = self._load_program_from_bytes(
                project,
                raw_bytes,
                effective_program_name,
                language=language,
                compiler=compiler,
                loader=loader,
            )
            self._finalize_open_program(program, project)
        except GhidraBackendError:
            if language or compiler or loader:
                raise
            suffix = Path(filename or "session.bin").suffix or ".bin"
            fallback_dir = (
                Path(self._config.workspace_root) / "runs" if self._config.workspace_root else None
            )
            if fallback_dir is not None:
                fallback_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                prefix="ghidra_headless_mcp-",
                suffix=suffix,
                dir=str(fallback_dir) if fallback_dir is not None else None,
                delete=False,
            ) as tmp:
                tmp.write(raw_bytes)
                temp_source_path = tmp.name
            opened = self.session_open(
                temp_source_path,
                update_analysis=update_analysis,
                read_only=read_only,
                project_location=project_location,
                project_name=project_name,
                program_name=effective_program_name,
            )
            fallback_record = self._get_record(opened["session_id"])
            fallback_record.temp_source_path = temp_source_path
            fallback_record.source_path = None
            return opened

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=project_root,
            project_name=effective_project_name,
            program_name=effective_program_name,
            program_path=f"/{effective_program_name}",
            source_path=None,
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=project_root if managed_project else None,
            temp_source_path=temp_source_path,
            program_consumer=consumer,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

        return self.binary_summary(session_id)

    def session_open_existing(
        self,
        project_location: str,
        project_name: str,
        *,
        program_path: str | None = None,
        folder_path: str = "/",
        program_name: str | None = None,
        read_only: bool = True,
        update_analysis: bool = False,
    ) -> dict[str, Any]:
        self._ensure_started()
        if not project_location:
            raise GhidraBackendError("project_location is required")
        if not project_name:
            raise GhidraBackendError("project_name is required")

        shared_project = self._find_open_project(project_location, project_name) is not None
        project = self._open_existing_project(project_location, project_name)
        if program_path:
            normalized = program_path if program_path.startswith("/") else f"/{program_path}"
            folder_path, _, tail = normalized.rpartition("/")
            folder_path = folder_path or "/"
            program_name = tail
        if not program_name:
            raise GhidraBackendError("program_name or program_path is required")

        try:
            program = project.openProgram(folder_path, program_name, False)
        except Exception as exc:
            if not shared_project:
                project.close()
            raise GhidraBackendError(f"failed to open program from project: {exc}") from exc
        if program is None:
            if not shared_project:
                project.close()
            raise GhidraBackendError("failed to open program from project: no Program returned")
        self._finalize_open_program(program, project)

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=str(Path(project_location).resolve()),
            project_name=project_name,
            program_name=program_name,
            program_path=f"{folder_path.rstrip('/')}/{program_name}"
            if folder_path != "/"
            else f"/{program_name}",
            source_path=None,
            read_only=read_only,
            managed_project=False,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

        return self.binary_summary(session_id)

    def session_close(self, session_id: str) -> dict[str, Any]:
        record = self._sessions.pop(session_id, None)
        if record is None:
            raise GhidraBackendError(f"unknown session_id: {session_id}")
        project_still_in_use = self._project_in_use(
            record.project_location,
            record.project_name,
            excluding_session_id=session_id,
        )

        with suppress(Exception):
            if record.decompiler is not None:
                record.decompiler.closeProgram()
                record.decompiler.dispose()

        if record.program_consumer is not None:
            with suppress(Exception):
                record.program.release(record.program_consumer)

        with suppress(Exception):
            record.project.close(record.program)
        if not project_still_in_use:
            with suppress(Exception):
                record.project.close()

        if record.temp_source_path:
            with suppress(OSError):
                Path(record.temp_source_path).unlink()
        if record.managed_project_root and not project_still_in_use:
            shutil.rmtree(record.managed_project_root, ignore_errors=True)

        return {"closed": True, "session_id": session_id}

    def session_list(self) -> dict[str, Any]:
        return {
            "sessions": [self.binary_summary(session_id) for session_id in sorted(self._sessions)],
            "count": len(self._sessions),
        }

    def session_mode(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        return {
            "session_id": session_id,
            "read_only": record.read_only,
            "deterministic": self._deterministic,
            "deterministic_scope": "process",
            "active_transaction": self._transaction_summary(record),
        }

    def session_set_mode(
        self,
        session_id: str,
        *,
        read_only: bool | None = None,
        deterministic: bool | None = None,
    ) -> dict[str, Any]:
        record = self._get_record(session_id)
        if read_only is not None:
            record.read_only = read_only
        if deterministic is not None and deterministic != self._deterministic:
            raise GhidraBackendError(
                "deterministic mode is process-level in Ghidra and cannot be changed after startup"
            )
        return self.session_mode(session_id)

    def binary_summary(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        program = record.program
        entry = None
        with suppress(Exception):
            entry = record.flat_api.getEntryPoint()
        compiler_spec = None
        with suppress(Exception):
            compiler_spec = program.getCompilerSpec().getCompilerSpecID().toString()
        return {
            "session_id": session_id,
            "filename": record.source_path or record.program_name,
            "program_name": record.program_name,
            "program_path": record.program_path,
            "project_location": record.project_location,
            "project_name": record.project_name,
            "language_id": program.getLanguageID().toString(),
            "compiler_spec_id": compiler_spec,
            "format": program.getExecutableFormat(),
            "entry_point": self._addr_str(entry),
            "image_base": self._addr_str(program.getImageBase()),
            "min_address": self._addr_str(program.getMinAddress()),
            "max_address": self._addr_str(program.getMaxAddress()),
            "read_only": record.read_only,
        }

    def session_save(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before save")
        try:
            record.project.save(record.program)
        except Exception as exc:
            raise GhidraBackendError(f"failed to save program: {exc}") from exc
        self._finalize_open_program(record.program, record.project)
        payload = self.binary_summary(session_id)
        payload["saved"] = True
        return payload

    def session_save_as(
        self,
        session_id: str,
        *,
        program_name: str,
        folder_path: str = "/",
        overwrite: bool = True,
    ) -> dict[str, Any]:
        if not program_name:
            raise GhidraBackendError("program_name is required")
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before save_as")
        try:
            record.project.saveAs(record.program, folder_path, program_name, overwrite)
        except Exception as exc:
            raise GhidraBackendError(f"failed to save program as '{program_name}': {exc}") from exc
        self._finalize_open_program(record.program, record.project)
        record.program_name = program_name
        record.program_path = (
            f"{folder_path.rstrip('/')}/{program_name}"
            if folder_path != "/"
            else f"/{program_name}"
        )
        payload = self.binary_summary(session_id)
        payload["saved_as"] = True
        return payload

    def session_export_project(self, session_id: str, *, destination: str) -> dict[str, Any]:
        if not destination:
            raise GhidraBackendError("destination is required")
        if not self._config.allow_export:
            raise GhidraBackendError(
                "project.export is disabled; set RYUUMONBUCHI_ALLOW_EXPORT=1 to enable"
            )
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before export")
        self.session_save(session_id)
        dest_root = Path(destination).resolve()
        self._reject_unsafe_export_target(dest_root)
        if dest_root.exists():
            raise GhidraBackendError(f"destination already exists: {dest_root}")
        dest_root.mkdir(parents=True, exist_ok=False)
        copied: list[str] = []
        for source in self._project_artifacts(record):
            if not source.exists():
                continue
            target = dest_root / source.name
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
            copied.append(str(target))
        return {
            "session_id": session_id,
            "destination": str(dest_root),
            "count": len(copied),
            "items": copied,
        }

    def session_export_binary(
        self,
        session_id: str,
        *,
        path: str,
        format: str = "original_file",
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        if not self._config.allow_export:
            raise GhidraBackendError(
                "program.export_binary is disabled; set RYUUMONBUCHI_ALLOW_EXPORT=1 to enable"
            )
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before export")
        self._ensure_started()
        if format not in {"original_file", "raw"}:
            raise GhidraBackendError("format must be 'original_file' or 'raw'")
        from ghidra.app.util.exporter import BinaryExporter, OriginalFileExporter
        from java.io import File
        from java.util import ArrayList

        output_path = Path(path).resolve()
        self._reject_unsafe_export_target(output_path)
        if output_path.exists() and not output_path.is_file():
            raise GhidraBackendError(f"destination is not a regular file: {output_path}")
        tmp_name, final_name = self._export_stage_file(output_path)
        exporter = OriginalFileExporter() if format == "original_file" else BinaryExporter()
        exporter.setOptions(ArrayList())
        try:
            ok = exporter.export(
                File(tmp_name),
                record.program,
                None,
                self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT),
            )
        except Exception as exc:
            with suppress(OSError):
                Path(tmp_name).unlink()
            raise GhidraBackendError(f"failed to export binary: {exc}") from exc
        if not ok:
            with suppress(OSError):
                Path(tmp_name).unlink()
            raise GhidraBackendError("failed to export binary")
        Path(tmp_name).chmod(0o600)
        self._export_publish(tmp_name, output_path, overwrite=True)
        return {
            "session_id": session_id,
            "path": final_name,
            "format": format,
            "size": output_path.stat().st_size,
        }

    def program_export_packed(
        self,
        session_id: str,
        *,
        destination_path: str,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Export the program as a lossless Ghidra packed file (GZF)."""
        if not destination_path:
            raise GhidraBackendError("destination_path is required")
        if not self._config.allow_export:
            raise GhidraBackendError(
                "program.export_packed is disabled; set RYUUMONBUCHI_ALLOW_EXPORT=1 to enable"
            )
        record = self._get_record(session_id)
        self._ensure_started()
        from java.io import File

        dest = Path(destination_path).expanduser().resolve()
        self._reject_unsafe_export_target(dest)
        if dest.exists() and not overwrite:
            raise GhidraBackendError(f"destination already exists: {dest}")
        if dest.exists() and dest.is_dir():
            raise GhidraBackendError(f"destination is a directory: {dest}")
        tmp_name = self._reserve_unique_path(dest)
        final_name = str(dest)
        try:
            record.program.saveToPackedFile(
                File(tmp_name),
                self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT),
            )
            Path(tmp_name).chmod(0o600)
            self._export_publish(tmp_name, dest, overwrite=overwrite)
        except GhidraBackendError:
            raise
        except Exception as exc:
            with suppress(OSError):
                Path(tmp_name).unlink()
            raise GhidraBackendError(f"failed to export packed file: {exc}") from exc
        return {
            "session_id": session_id,
            "destination_path": final_name,
            "size": dest.stat().st_size,
        }

    def _reject_unsafe_export_target(self, dest: Path) -> None:
        """Reject destinations that are symlinks or inside a symlinked parent."""
        resolved = dest.resolve(strict=False)
        for part in [*resolved.parents, resolved]:
            if part.is_symlink():
                raise GhidraBackendError(f"refusing to export through a symlink path: {dest}")

    def _export_stage_file(self, dest: Path) -> tuple[str, str]:
        """Stage to a unique mode-0600 sibling, return (tmp, final) paths."""
        parent = dest.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{dest.name}.",
            suffix=".tmp",
            dir=str(parent),
        )
        os.close(fd)
        Path(tmp_name).chmod(0o600)
        return tmp_name, str(dest)

    def _reserve_unique_path(self, dest: Path) -> str:
        """Reserve a unique sibling path that does NOT yet exist."""
        parent = dest.parent
        parent.mkdir(parents=True, exist_ok=True)
        for _ in range(1000):
            candidate = parent / f".{dest.name}.{uuid4().hex}.gzf"
            if not candidate.exists():
                return str(candidate)
        raise GhidraBackendError("failed to allocate a unique export path")

    def _export_publish(self, tmp_name: str, dest: Path, *, overwrite: bool) -> None:
        """Atomically publish a staged file, never pre-unlinking the target."""
        if dest.exists() or dest.is_symlink():
            if not overwrite:
                Path(tmp_name).unlink()
                raise GhidraBackendError(f"destination already exists: {dest}")
            if dest.is_dir():
                Path(tmp_name).unlink()
                raise GhidraBackendError(f"destination is a directory: {dest}")
        try:
            Path(tmp_name).replace(dest)
        except OSError:
            with suppress(OSError):
                Path(tmp_name).unlink()
            raise

    def project_file_delete(
        self,
        session_id: str,
        *,
        path: str,
    ) -> dict[str, Any]:
        """Delete a project file by exact project path; reject an open domain object."""
        if not path:
            raise GhidraBackendError("path is required")
        record = self._get_record(session_id)
        # Reject if any open session has this program path
        for other in self._sessions.values():
            if other.program_path == path:
                raise GhidraBackendError(f"cannot delete open program: {path}")
        project = record.project
        domain_file = project.getFile(path)
        if domain_file is None:
            raise GhidraBackendError(f"project file not found: {path}")
        if not domain_file.delete():
            raise GhidraBackendError(f"failed to delete project file: {path}")
        return {
            "session_id": session_id,
            "path": path,
            "deleted": True,
        }

    def metadata_store(self, session_id: str, *, key: str, value: Any) -> dict[str, Any]:
        if not key:
            raise GhidraBackendError("key is required")
        options = self._metadata_options(session_id)
        serialized = json.dumps(value, sort_keys=True)

        def mutate() -> None:
            with suppress(Exception):
                options.registerOption(key, "", None, "Stored by Ghidra Headless MCP")
            options.setString(key, serialized)

        self._with_write(session_id, f"Store metadata {key}", mutate)
        return {"session_id": session_id, "key": key, "value": value}

    def metadata_query(
        self,
        session_id: str,
        *,
        key: str | None = None,
        prefix: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._metadata_options(session_id)
        names = sorted(str(name) for name in options.getOptionNames())
        if key is not None:
            names = [name for name in names if name == key]
        if prefix is not None:
            names = [name for name in names if name.startswith(prefix)]
        items = []
        for name in names[offset : offset + limit]:
            raw = options.getString(name, None)
            try:
                parsed = json.loads(raw) if raw is not None else None
            except json.JSONDecodeError:
                parsed = raw
            items.append({"key": name, "value": parsed, "raw": raw})
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def report_program_summary(self, session_id: str) -> dict[str, Any]:
        summary = self.binary_summary(session_id)
        functions = self.binary_functions(session_id, offset=0, limit=10)
        strings = self.binary_strings(session_id, offset=0, limit=10)
        imports = self.binary_imports(session_id, offset=0, limit=10)
        blocks = self.binary_memory_blocks(session_id)
        return {
            "session_id": session_id,
            "summary": summary,
            "function_count": functions["total"],
            "string_count": self.binary_strings(session_id, offset=0, limit=1)["total"],
            "import_count": imports["total"],
            "memory_block_count": blocks["count"],
            "sample_functions": functions["items"],
            "sample_strings": strings["items"],
            "sample_imports": imports["items"],
        }

    def binary_rebase(
        self,
        session_id: str,
        *,
        image_base: int | str,
        commit: bool = True,
    ) -> dict[str, Any]:
        new_base = self._coerce_address(session_id, image_base, "image_base")
        old_base = self._get_program(session_id).getImageBase()

        def mutate() -> None:
            self._get_program(session_id).setImageBase(new_base, commit)

        self._with_write(session_id, f"Rebase program to {self._addr_str(new_base)}", mutate)
        return {
            "session_id": session_id,
            "old_image_base": self._addr_str(old_base),
            "new_image_base": self._addr_str(self._get_program(session_id).getImageBase()),
            "committed": commit,
        }

    def undo_begin(
        self, session_id: str, *, description: str = "MCP Transaction"
    ) -> dict[str, Any]:
        record = self._get_record(session_id)
        self._require_writable_session(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("session already has an active transaction")
        tx_id = int(record.program.startTransaction(description))
        record.active_transaction_id = tx_id
        record.active_transaction_description = description
        return self.undo_status(session_id)

    def undo_commit(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is None:
            raise GhidraBackendError("session has no active transaction")
        record.program.endTransaction(record.active_transaction_id, True)
        record.active_transaction_id = None
        record.active_transaction_description = None
        return self.undo_status(session_id)

    def undo_revert(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is None:
            raise GhidraBackendError("session has no active transaction")
        record.program.endTransaction(record.active_transaction_id, False)
        record.active_transaction_id = None
        record.active_transaction_description = None
        return self.undo_status(session_id)

    def undo_undo(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before undo")
        if not record.program.canUndo():
            raise GhidraBackendError("program cannot undo")
        record.program.undo()
        return self.undo_status(session_id)

    def undo_redo(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before redo")
        if not record.program.canRedo():
            raise GhidraBackendError("program cannot redo")
        record.program.redo()
        return self.undo_status(session_id)

    def undo_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        payload = {
            "session_id": session_id,
            "can_undo": bool(record.program.canUndo()),
            "can_redo": bool(record.program.canRedo()),
            "active_transaction": self._transaction_summary(record),
        }
        with suppress(Exception):
            payload["undo_name"] = record.program.getUndoName()
        with suppress(Exception):
            payload["redo_name"] = record.program.getRedoName()
        return payload

    def call_api(
        self,
        target: str,
        *,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        session_id: str | None = None,
        write: bool = False,
    ) -> dict[str, Any]:
        if not target:
            raise GhidraBackendError("target is required")
        args = args or []
        kwargs = kwargs or {}
        transitioned_session_ids = self._prepare_raw_access(session_id, write=write)
        root, attr_path = self._resolve_call_target(target, session_id)
        obj = self._resolve_attr_path(root, attr_path)
        try:
            result = obj(*args, **kwargs) if callable(obj) else obj
        except Exception as exc:
            raise GhidraBackendError(f"API call failed: {exc}") from exc
        return {
            "target": target,
            "callable": callable(obj),
            "result": self._to_jsonable(result),
            "mode_transitioned": bool(transitioned_session_ids),
            "transitioned_session_ids": transitioned_session_ids,
        }

    def eval_code(
        self,
        code: str,
        *,
        session_id: str | None = None,
        write: bool = False,
    ) -> dict[str, Any]:
        if not code:
            raise GhidraBackendError("code is required")
        self._ensure_started()
        transitioned_session_ids = self._prepare_raw_access(
            session_id,
            write=write,
            all_sessions=write and session_id is None,
        )
        context = self._eval_context(
            session_id,
            expose_sessions=write or session_id is not None,
        )
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                compiled = compile(code, "<ghidra_headless_mcp>", "eval")
            except SyntaxError:
                compiled = compile(code, "<ghidra_headless_mcp>", "exec")
                exec(compiled, context, context)  # noqa: S102
                result = context.get("_")
            else:
                result = eval(compiled, context, context)  # noqa: S307
        payload: dict[str, Any] = {"result": self._to_jsonable(result)}
        if stdout_buffer.getvalue():
            payload["stdout"] = stdout_buffer.getvalue()
        if stderr_buffer.getvalue():
            payload["stderr"] = stderr_buffer.getvalue()
        payload["mode_transitioned"] = bool(transitioned_session_ids)
        payload["transitioned_session_ids"] = transitioned_session_ids
        return payload

    def run_script(
        self,
        path: str,
        *,
        session_id: str | None = None,
        script_args: list[str] | None = None,
        write: bool = False,
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        self._ensure_started()
        if session_id is None:
            raise GhidraBackendError("session_id is required")
        record = self._get_record(session_id)
        transitioned_session_ids = self._prepare_raw_access(session_id, write=write)
        try:
            stdout_text, stderr_text = self._pyghidra.ghidra_script(
                path,
                record.project.getProject(),
                record.program,
                script_args=script_args or [],
                echo_stdout=False,
                echo_stderr=False,
            )
        except Exception as exc:
            raise GhidraBackendError(f"failed to run Ghidra script: {exc}") from exc
        payload: dict[str, Any] = {
            "path": path,
            "session_id": session_id,
            "mode_transitioned": bool(transitioned_session_ids),
            "transitioned_session_ids": transitioned_session_ids,
        }
        if stdout_text:
            payload["stdout"] = stdout_text
        if stderr_text:
            payload["stderr"] = stderr_text
        return payload

    def project_folders_list(
        self,
        session_id: str,
        *,
        folder_path: str = "/",
        recursive: bool = False,
    ) -> dict[str, Any]:
        folder = self._project_folder(session_id, folder_path)
        folders = self._walk_project_folders(folder) if recursive else list(folder.getFolders())
        items = [self._domain_folder_record(item) for item in folders]
        return {
            "session_id": session_id,
            "folder_path": folder.getPathname(),
            "recursive": recursive,
            "count": len(items),
            "items": items,
        }

    def project_files_list(
        self,
        session_id: str,
        *,
        folder_path: str = "/",
        recursive: bool = False,
        content_type: str | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        folder = self._project_folder(session_id, folder_path)
        files = self._walk_project_files(folder) if recursive else list(folder.getFiles())
        if content_type:
            files = [item for item in files if str(item.getContentType()) == content_type]
        if query:
            needle = query.lower()
            files = [
                item
                for item in files
                if needle in item.getPathname().lower() or needle in item.getName().lower()
            ]
        items = [self._domain_file_record(item) for item in files[offset : offset + limit]]
        return {
            "session_id": session_id,
            "folder_path": folder.getPathname(),
            "recursive": recursive,
            "offset": offset,
            "limit": limit,
            "total": len(files),
            "count": len(items),
            "items": items,
        }

    def project_file_info(self, session_id: str, *, path: str) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        return {
            "session_id": session_id,
            "file": self._domain_file_record(self._project_file(session_id, path)),
        }

    def project_program_open(
        self,
        session_id: str,
        *,
        path: str,
        read_only: bool | None = None,
        update_analysis: bool = False,
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        record = self._get_record(session_id)
        clean_path = path if path.startswith("/") else f"/{path}"
        folder_path, _, program_name = clean_path.rpartition("/")
        return self.session_open_existing(
            record.project_location,
            record.project_name,
            program_path=clean_path,
            folder_path=folder_path or "/",
            program_name=program_name,
            read_only=record.read_only if read_only is None else read_only,
            update_analysis=update_analysis,
        )

    def project_search_programs(
        self,
        session_id: str,
        *,
        query: str | None = None,
        content_type: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        effective_type = content_type or "Program"
        return self.project_files_list(
            session_id,
            folder_path="/",
            recursive=True,
            content_type=effective_type,
            query=query,
            offset=offset,
            limit=limit,
        )

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._startup_lock:
            if self._started:
                return
            self._prune_conflicting_sys_path_entries()
            launcher = self._pyghidra.HeadlessPyGhidraLauncher(
                install_dir=Path(self._install_dir) if self._install_dir else None,
            )
            launcher.add_vmargs("-Xms64m", f"-Xmx{self._config.max_heap_mb}m")
            for arg in self._config.vm_args:
                launcher.add_vmargs(arg)
            for cp in self._config.classpaths:
                launcher.add_classpath(cp)
            for cf in self._config.class_files:
                launcher.add_class_file(cf)
            self._launcher = launcher.start()
            self._started = True

    def _prune_conflicting_sys_path_entries(self) -> None:
        removable: list[str] = []
        for entry in list(sys.path):
            path = Path.cwd() if not entry else Path(entry)
            with suppress(OSError):
                if (path / "ghidra" / "Ghidra" / "application.properties").exists():
                    removable.append(entry)
        for entry in removable:
            with suppress(ValueError):
                sys.path.remove(entry)

    def _allocate_project(
        self,
        seed_name: str,
        *,
        project_location: str | None,
        project_name: str | None,
    ) -> tuple[str, str, bool]:
        if project_location or project_name:
            if not project_location:
                raise GhidraBackendError(
                    "project_location is required when project_name is supplied"
                )
            return (
                str(Path(project_location).resolve()),
                project_name or self._default_project_name(seed_name),
                False,
            )
        if self._config.workspace_root:
            base = Path(self._config.workspace_root) / "projects"
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            temp_root = tempfile.mkdtemp(prefix="ghidra_headless_mcp-", dir=str(base))
        else:
            temp_root = tempfile.mkdtemp(prefix="ghidra_headless_mcp-")
        return temp_root, self._default_project_name(seed_name), True

    def _default_project_name(self, seed_name: str) -> str:
        stem = Path(seed_name).name or "program"
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem) + "_ghidra"

    def _find_open_project(self, project_location: str, project_name: str) -> Any:
        resolved_location = str(Path(project_location).resolve())
        for record in self._sessions.values():
            if record.project_location == resolved_location and record.project_name == project_name:
                return record.project
        return None

    def _project_in_use(
        self,
        project_location: str,
        project_name: str,
        *,
        excluding_session_id: str | None = None,
    ) -> bool:
        resolved_location = str(Path(project_location).resolve())
        return any(
            session_id != excluding_session_id
            and record.project_location == resolved_location
            and record.project_name == project_name
            for session_id, record in self._sessions.items()
        )

    def _open_or_create_project(self, project_location: str, project_name: str) -> Any:
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        existing = self._find_open_project(project_location, project_name)
        if existing is not None:
            return existing

        locator = ProjectLocator(project_location, project_name)
        try:
            if locator.exists():
                return GhidraProject.openProject(project_location, project_name)
            Path(project_location).mkdir(parents=True, exist_ok=True)
            return GhidraProject.createProject(project_location, project_name, False)
        except Exception as exc:
            raise GhidraBackendError(f"failed to open project: {exc}") from exc

    def _open_existing_project(self, project_location: str, project_name: str) -> Any:
        from ghidra.base.project import GhidraProject

        existing = self._find_open_project(project_location, project_name)
        if existing is not None:
            return existing

        try:
            return GhidraProject.openProject(project_location, project_name)
        except Exception as exc:
            raise GhidraBackendError(f"failed to open project: {exc}") from exc

    def _resolve_loader_class(self, loader_name: str | None) -> Any:
        if not loader_name:
            return None
        from jpype import JClass

        try:
            return JClass(loader_name)
        except Exception as exc:
            raise GhidraBackendError(f"invalid loader class '{loader_name}': {exc}") from exc

    def _get_language(self, language_id: str) -> Any:
        from ghidra.program.model.lang import LanguageID, LanguageNotFoundException
        from ghidra.program.util import DefaultLanguageService

        try:
            return DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        except LanguageNotFoundException as exc:
            raise GhidraBackendError(f"invalid language id: {language_id}") from exc

    def _get_compiler_spec(self, language: Any, compiler_id: str | None) -> Any:
        if compiler_id is None:
            return language.getDefaultCompilerSpec()
        from ghidra.program.model.lang import CompilerSpecID, CompilerSpecNotFoundException

        try:
            return language.getCompilerSpecByID(CompilerSpecID(compiler_id))
        except CompilerSpecNotFoundException as exc:
            raise GhidraBackendError(f"invalid compiler spec id: {compiler_id}") from exc

    def _import_or_open_program(
        self,
        project: Any,
        path: str,
        program_name: str,
        *,
        language: str | None,
        compiler: str | None,
        loader: str | None,
    ) -> Any:
        existing = project.getRootFolder().getFile(program_name)
        if existing is not None:
            try:
                return project.openProgram("/", program_name, False)
            except Exception as exc:
                raise GhidraBackendError(
                    f"failed to open existing program '{program_name}': {exc}"
                ) from exc

        from java.io import File

        loader_class = self._resolve_loader_class(loader)
        try:
            if language is None:
                if loader_class is None:
                    program = project.importProgram(File(path))
                else:
                    program = project.importProgram(File(path), loader_class)
            else:
                lang = self._get_language(language)
                comp = self._get_compiler_spec(lang, compiler)
                if loader_class is None:
                    program = project.importProgram(File(path), lang, comp)
                else:
                    program = project.importProgram(File(path), loader_class, lang, comp)
        except Exception as exc:
            raise GhidraBackendError(f"failed to import program: {exc}") from exc
        if program is None:
            raise GhidraBackendError("failed to import program")
        try:
            project.saveAs(program, "/", program_name, True)
        except Exception as exc:
            project.close(program)
            raise GhidraBackendError(f"failed to save imported program: {exc}") from exc
        return program

    def _load_program_from_bytes(
        self,
        project: Any,
        raw_bytes: bytes,
        program_name: str,
        *,
        language: str | None,
        compiler: str | None,
        loader: str | None,
    ) -> tuple[Any, Any]:
        from java.lang import Object
        from jpype.types import JArray, JByte

        builder = self._pyghidra.program_loader().project(project.getProject()).name(program_name)
        builder = builder.source(JArray(JByte)(raw_bytes))
        if loader:
            builder = builder.loaders(loader)
        if language:
            builder = builder.language(language)
        if compiler:
            builder = builder.compiler(compiler)
        try:
            results = builder.load()
            results.save(self._pyghidra.task_monitor())
            consumer = Object()
            program = results.getPrimaryDomainObject(consumer)
            results.close()
            return program, consumer
        except Exception as exc:
            raise GhidraBackendError(f"failed to import program from bytes: {exc}") from exc

    def _register_session(
        self,
        *,
        project: Any,
        program: Any,
        project_location: str,
        project_name: str,
        program_name: str,
        program_path: str,
        source_path: str | None,
        read_only: bool,
        managed_project: bool,
        managed_project_root: str | None = None,
        temp_source_path: str | None = None,
        program_consumer: Any = None,
    ) -> str:
        from ghidra.program.flatapi import FlatProgramAPI

        session_id = uuid4().hex
        self._sessions[session_id] = SessionRecord(
            session_id=session_id,
            project=project,
            program=program,
            flat_api=FlatProgramAPI(program),
            program_name=program_name,
            program_path=program_path,
            project_location=project_location,
            project_name=project_name,
            source_path=source_path,
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=managed_project_root,
            temp_source_path=temp_source_path,
            program_consumer=program_consumer,
        )
        return session_id

    def _transition_sessions_to_writable(self, session_ids: Iterable[str]) -> list[str]:
        transitioned: list[str] = []
        for session_id in session_ids:
            if session_id is None:
                continue
            record = self._get_record(session_id)
            if record.read_only:
                record.read_only = False
                transitioned.append(session_id)
        return transitioned

    def _prepare_raw_access(
        self,
        session_id: str | None,
        *,
        write: bool,
        all_sessions: bool = False,
    ) -> list[str]:
        if all_sessions:
            return self._transition_sessions_to_writable(sorted(self._sessions))
        if session_id is None:
            return []
        record = self._get_record(session_id)
        if record.read_only and not write:
            raise GhidraBackendError(
                f"session {session_id} is read-only; pass write=true to use raw Ghidra tools"
            )
        return self._transition_sessions_to_writable([session_id]) if write else []

    def _open_transaction_entry_ids(self, transaction: Any) -> list[int]:
        transaction_class = transaction.getClass()
        base_id_field = transaction_class.getDeclaredField("baseId")
        entries_field = transaction_class.getDeclaredField("list")
        base_id_field.setAccessible(True)
        entries_field.setAccessible(True)
        base_id = int(base_id_field.get(transaction))
        entries = entries_field.get(transaction)
        open_ids: list[int] = []
        for index in range(entries.size()):
            entry = entries.get(index)
            entry_class = entry.getClass()
            status_field = entry_class.getDeclaredField("status")
            status_field.setAccessible(True)
            if str(status_field.get(entry)) == "NOT_DONE":
                open_ids.append(base_id + index)
        return open_ids

    def _drain_internal_transactions(self, program: Any, *, commit: bool = True) -> None:
        allowed_descriptions = {
            "",
            "Analysis",
            "Analyze",
            "Batch Processing",
            "Mark Program Analyzed",
        }
        while True:
            transaction = program.getCurrentTransactionInfo()
            if transaction is None:
                return
            if str(transaction.getDescription() or "") not in allowed_descriptions:
                return
            entry_ids = self._open_transaction_entry_ids(transaction)
            if not entry_ids:
                return
            program.endTransaction(entry_ids[-1], commit)

    def _sync_project_open_transaction(
        self, project: Any, program: Any, transaction_id: int
    ) -> None:
        from java.lang import Integer

        project_class = project.getClass()
        open_programs_field = project_class.getDeclaredField("openPrograms")
        open_programs_field.setAccessible(True)
        open_programs = open_programs_field.get(project)
        if open_programs is not None and open_programs.containsKey(program):
            open_programs.put(program, Integer.valueOf(int(transaction_id)))

    def _finalize_open_program(self, program: Any, project: Any | None = None) -> None:
        with suppress(Exception):
            self._drain_internal_transactions(program, commit=True)
        if project is not None:
            with suppress(Exception):
                self._sync_project_open_transaction(project, program, -1)

    def _transaction_summary(self, record: SessionRecord) -> dict[str, Any] | None:
        if record.active_transaction_id is None:
            return None
        return {
            "id": record.active_transaction_id,
            "description": record.active_transaction_description,
        }

    def _metadata_options(self, session_id: str) -> Any:
        return self._get_program(session_id).getOptions("GhidraHeadlessMCP Metadata")

    def _project_artifacts(self, record: SessionRecord) -> list[Path]:
        base = Path(record.project_location)
        return [
            base / f"{record.project_name}.gpr",
            base / f"{record.project_name}.rep",
        ]

    def _resolve_call_target(self, target: str, session_id: str | None) -> tuple[Any, str]:
        self._ensure_started()
        if target.startswith("pyghidra."):
            return self._pyghidra, target[9:]
        if target.startswith("program."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'program.'"
                )
            return self._get_program(session_id), target[8:]
        if target.startswith("project."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'project.'"
                )
            return self._get_record(session_id).project.getProject(), target[8:]
        if target.startswith("flat_api."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'flat_api.'"
                )
            return self._get_record(session_id).flat_api, target[9:]
        if target.startswith("decompiler."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'decompiler.'"
                )
            return self._get_decompiler(session_id), target[11:]
        if target.startswith("ghidra."):
            import ghidra

            return ghidra, target[7:]
        if target.startswith("java."):
            import java

            return java, target[5:]
        raise GhidraBackendError(
            "target must start with pyghidra., program., project., flat_api., decompiler., "
            "ghidra., or java."
        )

    def _resolve_attr_path(self, root: Any, attr_path: str) -> Any:
        if not attr_path:
            return root
        obj = root
        for part in attr_path.split("."):
            if not part:
                raise GhidraBackendError("invalid target path")
            if not hasattr(obj, part):
                raise GhidraBackendError(f"attribute not found: {part}")
            obj = getattr(obj, part)
        return obj

    def _eval_context(
        self,
        session_id: str | None,
        *,
        expose_sessions: bool = True,
    ) -> dict[str, Any]:
        self._ensure_started()
        import ghidra
        import java

        context: dict[str, Any] = {
            "pyghidra": self._pyghidra,
            "ghidra": ghidra,
            "java": java,
            "sessions": {
                sid: record.program
                for sid, record in self._sessions.items()
                if expose_sessions and not record.read_only
            },
        }
        if session_id is not None:
            record = self._get_record(session_id)
            context.update(
                {
                    "session_id": session_id,
                    "program": record.program,
                    "project": record.project.getProject(),
                    "ghidra_project": record.project,
                    "flat_api": record.flat_api,
                    "decompiler": self._get_decompiler(session_id),
                    "listing": record.program.getListing(),
                    "memory": record.program.getMemory(),
                    "symbol_table": record.program.getSymbolTable(),
                }
            )
        return context
