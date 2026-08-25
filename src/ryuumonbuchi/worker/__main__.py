"""Persistent worker child: frame loop, backend dispatch, IPC."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportMissingTypeStubs=false, reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false

from __future__ import annotations

import json
import os
import socket
import traceback
from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..backend import BackendConfig, GhidraBackend, GhidraBackendError
from ..catalog import TOOL_BY_NAME
from ..models import SCHEMA_VERSION, frame_message, parse_message, read_exact

_MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB
_SPILL_PREFIX_BYTES = 256 * 1024  # 256 KiB preview

# Inherited IPC socket, wrapped from the fd passed by the parent via
# RYUUMONBUCHI_WORKER_FD. Set once in main(); none before initialization.
_sock: socket.socket | None = None


def _build_config(raw: dict[str, Any]) -> BackendConfig:
    return BackendConfig(
        install_dir=raw.get("install_dir"),
        max_heap_mb=raw.get("max_heap_mb", 1024),
        max_cpu=raw.get("max_cpu", 2),
        vm_args=tuple(raw.get("vm_args", [])),
        classpaths=tuple(raw.get("classpaths", [])),
        class_files=tuple(raw.get("class_files", [])),
        deterministic=raw.get("deterministic", True),
        workspace_root=raw.get("workspace_root", ""),
        max_import_bytes=raw.get("max_import_bytes", 67_108_864),
        max_response_bytes=raw.get("max_response_bytes", 4_194_304),
        max_log_tail_bytes=raw.get("max_log_tail_bytes", 65_536),
        allow_export=raw.get("allow_export", False),
        allow_import_bytes=raw.get("allow_import_bytes", False),
    )


def _apply_cpu_affinity(max_cpu: int) -> int:
    allowed = list(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    if not allowed:
        raise RuntimeError("empty CPU affinity set")
    selected = sorted(allowed)[: max(1, min(max_cpu, len(allowed)))]
    os.sched_setaffinity(0, set(selected))  # type: ignore[attr-defined]
    return len(selected)


def _to_jsonable(obj: Any) -> Any:
    """Convert Java/Python objects to JSON-serializable forms."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    # Java objects via Jep — try common conversion
    with suppress(Exception):
        return str(obj)
    return str(obj)


def _should_spill(result: Any, max_response_bytes: int) -> bool:
    try:
        data = json.dumps(result, ensure_ascii=False, default=str)
        return len(data.encode("utf-8")) > max_response_bytes
    except (TypeError, ValueError):
        return False


def _spill_result(result: Any, workspace_root: str) -> dict[str, Any]:
    data = json.dumps(_to_jsonable(result), ensure_ascii=False, default=str)
    raw = data.encode("utf-8")
    run_dir = Path(workspace_root) / "runs"
    run_dir.mkdir(mode=0o700, exist_ok=True)
    spill_path = run_dir / f"result-{uuid4().hex}.json"
    fd = os.open(str(spill_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    written = 0
    try:
        view = memoryview(raw)
        while written < len(raw):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    preview = data[:_SPILL_PREFIX_BYTES]
    if len(data) > _SPILL_PREFIX_BYTES:
        preview += "...[truncated]"
    return {
        "spilled": True,
        "result_path": str(spill_path),
        "preview": preview,
        "total_bytes": len(raw),
    }


# Configured response byte cap, set once from the bootstrap config in main().
_max_response_bytes_configured = _MAX_RESPONSE_BYTES


def _send_response(payload: dict[str, Any]) -> None:
    if _sock is None:
        msg = "worker socket not initialized"
        raise AssertionError(msg)
    data = frame_message(payload)
    _sock.sendall(data)


def _send_success(request_id: str, result: Any, *, workspace_root: str = "") -> None:
    jsonable = _to_jsonable(result)
    if workspace_root and _should_spill(jsonable, _max_response_bytes_configured):
        spill = _spill_result(jsonable, workspace_root)
        response: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "request_id": request_id,
            "ok": True,
            "result": None,
            "spilled": True,
            "result_path": spill["result_path"],
            "preview": spill["preview"],
            "total_bytes": spill["total_bytes"],
        }
    else:
        response = {
            "schema": SCHEMA_VERSION,
            "request_id": request_id,
            "ok": True,
            "result": jsonable,
        }
    _send_response(response)


def _send_error(request_id: str, code: str, message: str, **extra: Any) -> None:
    error: dict[str, Any] = {"code": code, "message": message}
    error.update(extra)
    response = {
        "schema": SCHEMA_VERSION,
        "request_id": request_id,
        "ok": False,
        "error": error,
        "code": code,
    }
    _send_response(response)


def _dispatch_call(backend: GhidraBackend, tool: str, arguments: dict[str, Any]) -> Any:
    spec = TOOL_BY_NAME.get(tool)
    if spec is None:
        raise GhidraBackendError(f"unknown tool: {tool}")
    if spec.backend_method is None:
        raise GhidraBackendError(f"tool {tool} has no backend method")
    _validate_arguments(spec, arguments)
    method = getattr(backend, spec.backend_method)
    return method(**arguments)


def _validate_arguments(spec: Any, arguments: dict[str, Any]) -> None:
    import jsonschema

    try:
        jsonschema.validate(arguments, spec.input_schema, cls=jsonschema.Draft202012Validator)
    except jsonschema.ValidationError as exc:
        raise GhidraBackendError(f"argument validation failed: {exc.message}") from exc


def _dispatch_batch(
    backend: GhidraBackend,
    session_id: str,
    operations: list[dict[str, Any]],
) -> Any:
    results: list[dict[str, Any]] = []
    record = backend._get_record(session_id)  # noqa: SLF001
    any_mutates = False

    # Validate and classify
    validated: list[tuple[str, dict[str, Any], bool]] = []
    for op in operations:
        tool = op.get("tool")
        args = dict(op.get("arguments", {}))
        if "session_id" not in args:
            args["session_id"] = session_id
        elif args["session_id"] != session_id:
            raise GhidraBackendError(
                f"operation session_id mismatch: {args['session_id']} != {session_id}"
            )
        spec = TOOL_BY_NAME.get(tool)
        if spec is None:
            raise GhidraBackendError(f"unknown tool in batch: {tool}")
        if not spec.batch_allowed:
            raise GhidraBackendError(f"tool {tool} is not batchable")
        _validate_arguments(spec, args)
        mutates = not spec.read_only
        any_mutates = any_mutates or mutates
        validated.append((tool, args, spec.read_only))

    if any_mutates and record.read_only:
        raise GhidraBackendError("batch requires a writable session")

    tx_id: int | None = None
    try:
        if any_mutates:
            tx_id = int(
                backend._get_program(session_id).startTransaction(  # noqa: SLF001
                    "Ryuumonbuchi operation.batch"
                )
            )
            # Mark the outer transaction on the record so nested _with_write
            # calls reuse it instead of opening independent commits.
            record.active_transaction_id = tx_id
            record.active_transaction_description = "Ryuumonbuchi operation.batch"

        for tool, args, _read_only in validated:
            try:
                result = _dispatch_call(backend, tool, args)
                results.append({"tool": tool, "result": result})
            except Exception:
                if tx_id is not None:
                    backend._get_program(session_id).endTransaction(tx_id, False)  # noqa: SLF001
                    tx_id = None
                    record.active_transaction_id = None
                    record.active_transaction_description = None
                raise

        if tx_id is not None:
            backend._get_program(session_id).endTransaction(tx_id, True)  # noqa: SLF001
            tx_id = None
            record.active_transaction_id = None
            record.active_transaction_description = None
            with suppress(Exception):
                record.project.save(record.program)

    except Exception:
        if tx_id is not None:
            with suppress(Exception):
                backend._get_program(session_id).endTransaction(tx_id, False)  # noqa: SLF001
        record.active_transaction_id = None
        record.active_transaction_description = None
        raise

    return {"results": results}


def main() -> int:
    # The parent passes our IPC socket fd via the environment. pass_fds
    # preserves the parent's fd number verbatim (no remap), so it is not
    # necessarily 3; read it dynamically and wrap it into a socket object.
    sock_fd_raw = os.environ.get("RYUUMONBUCHI_WORKER_FD")
    if sock_fd_raw is None:
        return 1
    sock_fd = int(sock_fd_raw)
    os.set_blocking(sock_fd, True)
    global _sock
    _sock = socket.socket(fileno=sock_fd)

    # Read bootstrap frame
    header = read_exact(_sock, 8)
    if header is None or len(header) < 8:
        return 1
    import struct

    (length,) = struct.unpack(">Q", header)
    body = read_exact(_sock, length)
    if body is None or len(body) < length:
        return 1
    bootstrap = parse_message(body)
    raw_config = bootstrap.get("config", {})
    config = _build_config(raw_config)

    # Apply CPU affinity before importing PyGhidra
    effective_cpus = _apply_cpu_affinity(config.max_cpu)

    # Import PyGhidra and construct backend
    import pyghidra

    backend = GhidraBackend(pyghidra, config)
    workspace_root = raw_config.get("workspace_root", "")
    global _max_response_bytes_configured
    _max_response_bytes_configured = config.max_response_bytes

    # Frame loop
    while True:
        try:
            header = read_exact(_sock, 8)
        except OSError:
            break
        if header is None or len(header) < 8:
            break

        (length,) = struct.unpack(">Q", header)
        if length == 0:
            continue
        body = read_exact(_sock, length)
        if body is None or len(body) < length:
            break

        try:
            request = parse_message(body)
        except ValueError:
            # Can't respond without a request_id
            continue

        request_id = request.get("request_id", "")
        kind = request.get("kind", "")

        if kind == "shutdown":
            _send_success(request_id, {"shutdown": True})
            break

        if kind == "status":
            status = {
                "generation": backend._generation,  # noqa: SLF001
                "jvm_started": backend._started,  # noqa: SLF001
                "child_pid": os.getpid(),
                "effective_cpus": effective_cpus,
                "session_count": len(backend._sessions),  # noqa: SLF001
                "task_count": len(backend._tasks),  # noqa: SLF001
                "active_task_ids": list(backend._tasks),  # noqa: SLF001
            }
            _send_success(request_id, status)
            continue

        if kind == "call":
            try:
                tool = request.get("tool", "")
                arguments = request.get("arguments", {})
                result = _dispatch_call(backend, tool, arguments)
                _send_success(request_id, result, workspace_root=workspace_root)
            except GhidraBackendError as exc:
                _send_error(request_id, "ghidra_error", str(exc))
            except Exception as exc:
                tb = traceback.format_exc()
                if isinstance(exc, SystemExit):
                    _send_error(request_id, "worker_failed", f"worker exited: {exc}")
                    break
                _send_error(request_id, "ghidra_error", f"{exc}\n{tb}")
            continue

        if kind == "batch":
            try:
                session_id = request.get("session_id", "")
                operations = request.get("operations", [])
                result = _dispatch_batch(backend, session_id, operations)
                _send_success(request_id, result, workspace_root=workspace_root)
            except GhidraBackendError as exc:
                _send_error(request_id, "ghidra_error", str(exc))
            except Exception as exc:
                tb = traceback.format_exc()
                _send_error(request_id, "ghidra_error", f"{exc}\n{tb}")
            continue

        _send_error(request_id, "invalid_params", f"unknown request kind: {kind}")

    # Cleanup
    with suppress(Exception):
        backend.shutdown()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
