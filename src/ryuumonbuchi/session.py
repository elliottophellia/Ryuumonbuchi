# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Private per-process session projects and atomic manifests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, cast

from .config import safe_descendant

SESSION_SCHEMA = 1
PROJECT_NAME = "ryuumonbuchi"
_PROGRAM_NAME_PATTERN = re.compile(r"^[^/\\\x00]+$")


class SessionError(RuntimeError):
    """Raised when a session workspace or manifest transition is invalid."""


class ProgramNotSelectedError(SessionError):
    """Raised when a program-bound operation lacks a known program name."""


class ProgramExistsError(SessionError):
    """Raised when an import would replace an existing program."""


class ProgramNotFoundError(SessionError):
    """Raised when a requested program is absent from the manifest."""


class UncertainWorkerError(SessionError):
    """Raised when worker state cannot be trusted and the session was replaced."""


@dataclass(frozen=True, slots=True)
class ProgramRecord:
    """Manifest record for one explicitly named program."""

    program_name: str
    source_path: str
    source_sha256: str
    imported_at: str
    analyzed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "program_name": self.program_name,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "imported_at": self.imported_at,
            "analyzed": self.analyzed,
        }


@dataclass(frozen=True, slots=True)
class SessionManifest:
    """Validated on-disk session manifest."""

    session_id: str
    created_at: str
    ghidra_version: str
    programs: dict[str, ProgramRecord]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SESSION_SCHEMA,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "ghidra_version": self.ghidra_version,
            "programs": [record.as_dict() for record in self.programs.values()],
        }


@dataclass(slots=True)
class SessionWorkspace:
    """One private, non-reusable temporary root owned by one MCP process."""

    root: Path
    session_id: str
    ghidra_version: str
    manifest_path: Path
    project_dir: Path
    runs_dir: Path
    owner_lock_path: Path
    _lock_file: BinaryIO
    operation_lock: asyncio.Lock
    _closed: bool = False

    @classmethod
    def create(cls, ghidra_version: str, *, temp_dir: Path | None = None) -> SessionWorkspace:
        session_id = str(uuid.uuid4())
        base = Path(temp_dir) if temp_dir is not None else Path(tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        root = base / f"ryuumonbuchi-{session_id}"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        project_dir = root / "project"
        runs_dir = root / "runs"
        project_dir.mkdir(mode=0o700)
        runs_dir.mkdir(mode=0o700)
        owner_lock_path = root / "owner.lock"
        lock_file = owner_lock_path.open("a+b")
        try:
            _lock_exclusive(lock_file)
        except BaseException:
            lock_file.close()
            shutil.rmtree(root, ignore_errors=True)
            raise
        workspace = cls(
            root=root,
            session_id=session_id,
            ghidra_version=ghidra_version,
            manifest_path=root / "session.json",
            project_dir=project_dir,
            runs_dir=runs_dir,
            owner_lock_path=owner_lock_path,
            _lock_file=lock_file,
            operation_lock=asyncio.Lock(),
        )
        workspace._write_manifest(
            SessionManifest(session_id, datetime.now(UTC).isoformat(), ghidra_version, {})
        )
        return workspace

    @property
    def created_at(self) -> datetime:
        return datetime.fromisoformat(self.read_manifest().created_at)

    @property
    def project_path(self) -> Path:
        return self.project_dir / f"{PROJECT_NAME}.gpr"

    @property
    def project_repository_path(self) -> Path:
        return self.project_dir / f"{PROJECT_NAME}.rep"

    @property
    def closed(self) -> bool:
        return self._closed

    def read_manifest(self) -> SessionManifest:
        try:
            parsed: object = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"Session manifest is unreadable: {self.manifest_path}"
            raise SessionError(message) from exc
        if not isinstance(parsed, dict):
            message = "Session manifest must be an object"
            raise SessionError(message)
        data = cast(dict[str, object], parsed)
        if data.get("schema") != SESSION_SCHEMA:
            message = "Unsupported session manifest schema"
            raise SessionError(message)
        raw_programs_value = data.get("programs")
        if not isinstance(raw_programs_value, list):
            message = "Session manifest programs must be a list"
            raise SessionError(message)
        raw_programs = cast(list[object], raw_programs_value)
        programs: dict[str, ProgramRecord] = {}
        try:
            for raw_value in raw_programs:
                if not isinstance(raw_value, dict):
                    message = "program record is not an object"
                    raise TypeError(message)
                raw = cast(dict[str, object], raw_value)
                record = ProgramRecord(
                    program_name=validate_program_name(raw.get("program_name")),
                    source_path=str(raw.get("source_path")),
                    source_sha256=str(raw.get("source_sha256")),
                    imported_at=str(raw.get("imported_at")),
                    analyzed=bool(raw.get("analyzed")),
                )
                if record.program_name in programs:
                    message = f"Duplicate program in session manifest: {record.program_name}"
                    raise SessionError(message)
                programs[record.program_name] = record
            session_id = str(data["session_id"])
            created_at = str(data["created_at"])
            ghidra_version = str(data["ghidra_version"])
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, SessionError):
                raise
            message = "Session manifest has an invalid record"
            raise SessionError(message) from exc
        if session_id != self.session_id:
            message = "Session manifest belongs to another session"
            raise SessionError(message)
        return SessionManifest(session_id, created_at, ghidra_version, programs)

    def _write_manifest(self, manifest: SessionManifest) -> None:
        payload = json.dumps(
            manifest.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        temporary = self.manifest_path.with_name(
            f".{self.manifest_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.manifest_path)
            directory_fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    def update_program(self, record: ProgramRecord) -> None:
        manifest = self.read_manifest()
        programs = dict(manifest.programs)
        programs[record.program_name] = record
        self._write_manifest(
            SessionManifest(
                manifest.session_id, manifest.created_at, manifest.ghidra_version, programs
            )
        )

    def remove_program(self, program_name: str) -> ProgramRecord:
        name = validate_program_name(program_name)
        manifest = self.read_manifest()
        try:
            record = manifest.programs[name]
        except KeyError as exc:
            message = f"Program is not found: {name}"
            raise ProgramNotFoundError(message) from exc
        programs = dict(manifest.programs)
        del programs[name]
        self._write_manifest(
            SessionManifest(
                manifest.session_id, manifest.created_at, manifest.ghidra_version, programs
            )
        )
        return record

    def require_program(self, program_name: str | None) -> ProgramRecord:
        if (
            not program_name
            or not _PROGRAM_NAME_PATTERN.fullmatch(program_name)
            or program_name in {".", ".."}
        ):
            message = "Program is not selected: provide an imported program_name"
            raise ProgramNotSelectedError(message)
        record = self.read_manifest().programs.get(program_name)
        if record is None:
            message = "Program is not selected: provide an imported program_name"
            raise ProgramNotSelectedError(message)
        return record

    def ensure_program_absent(self, program_name: str) -> None:
        name = validate_program_name(program_name)
        if name in self.read_manifest().programs:
            message = f"Program already exists: {name}"
            raise ProgramExistsError(message)

    @asynccontextmanager
    async def operation(self) -> AsyncGenerator[None]:
        """Serialize one complete worker operation for this local project."""

        async with self.operation_lock:
            yield

    async def replace(self, ghidra_version: str) -> tuple[str, SessionWorkspace]:
        old_session_id = self.session_id
        await self.close()
        replacement = SessionWorkspace.create(ghidra_version, temp_dir=self.root.parent)
        return old_session_id, replacement

    async def close(self) -> None:
        if self._closed:
            return
        async with self.operation_lock:
            if self._closed:
                return
            _unlock(self._lock_file)
            self._lock_file.close()
            shutil.rmtree(self.root, ignore_errors=False)
            self._closed = True


def _lock_exclusive(handle: BinaryIO) -> None:
    if os.name != "posix":
        message = "Ryuumonbuchi requires POSIX file locking"
        raise SessionError(message)
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        message = "Session owner lock is already held"
        raise SessionError(message) from exc


def _unlock(handle: BinaryIO) -> None:
    if os.name == "posix":
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def try_cleanup_workspace(root: Path) -> bool:
    """Remove an explicitly supplied stale root only when its owner lock is free."""

    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        return False
    lock_path = resolved / "owner.lock"
    try:
        with lock_path.open("a+b") as handle:
            _lock_exclusive(handle)
            _unlock(handle)
    except (OSError, SessionError):
        return False
    shutil.rmtree(resolved)
    return True


def validate_program_name(program_name: object) -> str:
    """Validate an explicit root-level Ghidra program name."""

    if not isinstance(program_name, str) or not _PROGRAM_NAME_PATTERN.fullmatch(program_name):
        message = "program_name must be a non-empty root-level name without slash"
        raise ValueError(message)
    if program_name in {".", ".."} or len(program_name) > 128:
        message = "program_name must be a non-empty root-level name without slash"
        raise ValueError(message)
    program_name.encode("utf-8")
    return program_name


def stream_sha256(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Hash a regular readable file without loading it into memory."""

    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        message = f"Source file does not exist: {resolved}"
        raise FileNotFoundError(message)
    if not os.access(resolved, os.R_OK):
        message = f"Source file is not readable: {resolved}"
        raise PermissionError(message)
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def validate_workspace_path(path: Path, workspace: SessionWorkspace) -> Path:
    """Resolve a path and require it to stay below this session root."""

    resolved = path.expanduser().resolve()
    if not safe_descendant(resolved, workspace.root) or resolved == workspace.root:
        message = f"Path is outside the current session workspace: {resolved}"
        raise SessionError(message)
    return resolved
