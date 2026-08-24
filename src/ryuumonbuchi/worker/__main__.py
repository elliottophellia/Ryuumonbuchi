# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""One-shot worker command-line entrypoint and response serialization."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportMissingTypeStubs=false

from __future__ import annotations

import json
import os
import sys
import traceback
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

import pyghidra
from pydantic import ValidationError

from ..models import (
    BatchOperation,
    ProgramDeleteOperation,
    ProgramImportBytesOperation,
    ProgramImportOperation,
    WorkerError,
    WorkerFailure,
    WorkerOperation,
    WorkerRequest,
    WorkerSuccess,
)
from .context import WorkerContext, WorkerGhidraError
from .dispatch import execute_operation, parse_operation
from .operations import OperationError


def _write_response(
    path: Path,
    request_id: str,
    *,
    max_response_bytes: int,
    result: object = None,
    error: tuple[str, str] | None = None,
) -> None:
    if error is None:
        payload = WorkerSuccess(request_id=request_id, result=result).model_dump(
            mode="json", by_alias=True
        )
    else:
        payload = WorkerFailure(
            request_id=request_id,
            error=WorkerError(code=error[0], message=error[1]),
        ).model_dump(mode="json", by_alias=True)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_response_bytes and error is None:
        payload = WorkerFailure(
            request_id=request_id,
            error=WorkerError(
                code="response_too_large",
                message="worker response exceeds the configured byte limit",
            ),
        ).model_dump(mode="json", by_alias=True)
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_response_bytes:
        raise WorkerGhidraError("response_too_large: error response exceeds configured byte limit")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(encoded)
        handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _import_program(context: WorkerContext, operation: ProgramImportOperation) -> dict[str, Any]:
    monitor = pyghidra.task_monitor()
    loader = (
        pyghidra.program_loader()
        .source(operation.source_path)
        .project(context.project)
        .projectFolderPath("/")
        .name(operation.program_name)
        .monitor(monitor)
    )
    results = loader.load()
    saved_domain_file: Any = None
    try:
        results.save(monitor)
        saved_domain_file = results.getPrimary().getSavedDomainFile()
    finally:
        results.close()
    try:
        with context.writable_program(operation.program_name) as program:
            analyzed = False
            if operation.analyze:
                pyghidra.analyze(program, pyghidra.task_monitor())
                analyzed = True
            program.save("Imported by Ryuumonbuchi", pyghidra.task_monitor())
    except BaseException:
        if saved_domain_file is not None:
            with suppress(Exception):
                saved_domain_file.delete()
        raise
    return {"program_name": operation.program_name, "analyzed": analyzed}


def _import_program_bytes(
    context: WorkerContext, operation: ProgramImportBytesOperation
) -> dict[str, Any]:
    import base64
    import tempfile

    payload = base64.b64decode(operation.data, validate=True)
    with tempfile.TemporaryDirectory(prefix="ryuumonbuchi-import-") as directory:
        source = Path(directory) / operation.program_name
        source.write_bytes(payload)
        wrapped = ProgramImportOperation(
            source_path=str(source),
            program_name=operation.program_name,
            analyze=operation.analyze,
        )
        return _import_program(context, wrapped)


def _delete_program(context: WorkerContext, operation: ProgramDeleteOperation) -> dict[str, Any]:
    if context.project is None:
        raise WorkerGhidraError("Ghidra project is not open")
    domain_file = context.project.getProjectData().getFile(f"/{operation.program_name}")
    if domain_file is None:
        raise WorkerGhidraError(f"Program is not found: {operation.program_name}")
    domain_file.delete()
    return {"program_name": operation.program_name, "deleted": True}


def _execute_batch(
    context: WorkerContext, request: WorkerRequest, parsed: list[WorkerOperation]
) -> object:
    program_name = request.program_name
    if not program_name:
        raise OperationError("program_name is required in worker request envelope")
    operations = [cast(BatchOperation, operation) for operation in parsed]
    with context.program(program_name, read_only=request.read_only) as program:
        monitor = pyghidra.task_monitor()
        transaction_id: int | None = None
        try:
            if not request.read_only:
                transaction_id = program.startTransaction("Ryuumonbuchi batch")
            results: list[dict[str, Any]] = []
            for operation in operations:
                value = execute_operation(context, program, operation, monitor)
                results.append({"action": operation.action, "result": value})
            if transaction_id is not None:
                program.endTransaction(transaction_id, True)
                transaction_id = None
            if not request.read_only:
                program.save("Ryuumonbuchi operation", pyghidra.task_monitor())
        except BaseException:
            if transaction_id is not None:
                with suppress(Exception):
                    program.endTransaction(transaction_id, False)
            raise
    return results[0]["result"] if len(results) == 1 else {"results": results}


def worker_main(request_path: Path, response_path: Path) -> int:
    request_id = "unknown"
    max_response_bytes = 4_194_304
    context: WorkerContext | None = None
    result: object = None
    error: tuple[str, str] | None = None
    exit_code = 0
    try:
        request = WorkerRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
        request_id = request.request_id
        max_response_bytes = request.max_response_bytes
        context = WorkerContext(request)
        context.start()
        if len(request.operations) > 32:
            raise OperationError("worker batch exceeds 32 operations")
        parsed = [parse_operation(raw) for raw in request.operations]
        lifecycle = [
            operation
            for operation in parsed
            if isinstance(
                operation,
                (ProgramImportOperation, ProgramImportBytesOperation, ProgramDeleteOperation),
            )
        ]
        if lifecycle:
            if len(parsed) != 1:
                raise OperationError("program import/delete cannot be batched")
            operation = lifecycle[0]
            if isinstance(operation, ProgramImportOperation):
                result = _import_program(context, operation)
            elif isinstance(operation, ProgramImportBytesOperation):
                result = _import_program_bytes(context, operation)
            else:
                result = _delete_program(context, operation)
        else:
            result = _execute_batch(context, request, parsed)
    except ValidationError as exc:
        error = ("invalid_params", str(exc))
    except (OperationError, WorkerGhidraError, FileNotFoundError) as exc:
        error = ("ghidra_error", str(exc))
    except BaseException as exc:
        traceback.print_exc(file=sys.stderr)
        error = ("worker_failed", str(exc))
        exit_code = 1
    finally:
        if context is not None:
            try:
                context.close()
            except BaseException as exc:
                error = ("worker_cleanup_failed", str(exc))
                exit_code = 1
        with suppress(Exception):
            _write_response(
                response_path,
                request_id,
                max_response_bytes=max_response_bytes,
                result=result,
                error=error,
            )
    return exit_code


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: python -m ryuumonbuchi.worker REQUEST_JSON RESPONSE_JSON", file=sys.stderr)
        return 2
    return worker_main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
