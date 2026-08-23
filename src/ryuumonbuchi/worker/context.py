# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Typed ownership adapter for one headless PyGhidra request."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportMissingTypeStubs=false

from __future__ import annotations

import contextlib
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pyghidra

from ..models import WorkerRequest


class WorkerGhidraError(RuntimeError):
    """Raised when Ghidra cannot satisfy a typed worker operation."""


class WorkerContext:
    """Own launcher, project, program contexts, and request-local decompilers."""

    def __init__(self, request: WorkerRequest) -> None:
        self.request = request
        self.launcher: pyghidra.HeadlessPyGhidraLauncher | None = None
        self.project: Any = None
        self._decompilers: dict[str, Any] = {}
        self._closed = False

    def start(self) -> None:
        """Start Ghidra once inside this child process and open its private project."""

        self.launcher = pyghidra.HeadlessPyGhidraLauncher(
            verbose=False,
            install_dir=Path(self.request.ghidra_install_dir),
        )
        self.launcher.add_vmargs(
            "-Xms64m",
            f"-Xmx{self.request.max_heap_mb}m",
            f"-Dcpu.core.limit={self.request.max_cpu}",
            "-Djava.awt.headless=true",
        )
        self.launcher.start()
        self.project = pyghidra.open_project(
            Path(self.request.project_dir), self.request.project_name, create=True
        )

    @contextlib.contextmanager
    def writable_program(self, program_name: str) -> Generator[Any]:
        """Open exactly one root-level program with a released context consumer."""

        if self.project is None:
            raise WorkerGhidraError("Ghidra project is not open")
        try:
            with pyghidra.program_context(self.project, f"/{program_name}") as program:
                yield program
        except FileNotFoundError as exc:
            raise WorkerGhidraError(f"Program is not found: {program_name}") from exc

    @contextlib.contextmanager
    def readonly_program(self, program_name: str) -> Generator[Any]:
        """Open an exact domain file read-only with an explicit fresh consumer."""

        if self.project is None:
            raise WorkerGhidraError("Ghidra project is not open")
        consumer: Any = None
        program: Any = None
        try:
            from ghidra.framework.model import DomainFile
            from ghidra.program.model.listing import Program
            from java.lang import Object

            consumer = Object()
            domain_file = self.project.getProjectData().getFile(f"/{program_name}")
            if domain_file is None:
                raise WorkerGhidraError(f"Program is not found: {program_name}")
            program = domain_file.getReadOnlyDomainObject(
                consumer, DomainFile.DEFAULT_VERSION, pyghidra.task_monitor()
            )
            if not Program.class_.isAssignableFrom(program.getClass()):
                raise WorkerGhidraError(f"Project entry is not a Program: {program_name}")
            yield program
        except WorkerGhidraError:
            raise
        except Exception as exc:
            raise WorkerGhidraError(f"Cannot open program read-only: {program_name}") from exc
        finally:
            if program is not None and consumer is not None:
                with contextlib.suppress(Exception):
                    program.release(consumer)

    @contextlib.contextmanager
    def program(self, program_name: str, *, read_only: bool) -> Generator[Any]:
        """Select the ownership-safe writable or read-only context."""

        if read_only:
            with self.readonly_program(program_name) as program:
                yield program
        else:
            with self.writable_program(program_name) as program:
                yield program

    def decompiler(self, program: Any) -> Any:
        """Create or reuse one decompiler for this request and exact program."""

        key = str(program.getDomainFile().getPathname())
        if key in self._decompilers:
            return self._decompilers[key]
        from ghidra.app.decompiler import DecompInterface

        interface = DecompInterface()
        interface.toggleCCode(True)
        if not interface.openProgram(program):
            interface.dispose()
            raise WorkerGhidraError("Decompiler could not open the program")
        self._decompilers[key] = interface
        return interface

    def close(self) -> None:
        """Close every decompiler and project; preserve the first cleanup failure."""

        if self._closed:
            return
        first_error: BaseException | None = None
        for interface in self._decompilers.values():
            try:
                interface.closeProgram()
                interface.dispose()
            except BaseException as exc:
                first_error = first_error or exc
        self._decompilers.clear()
        if self.project is not None:
            try:
                self.project.close()
            except BaseException as exc:
                first_error = first_error or exc
        self.project = None
        self._closed = True
        if first_error is not None:
            raise WorkerGhidraError(f"Ghidra cleanup failed: {first_error}") from first_error
