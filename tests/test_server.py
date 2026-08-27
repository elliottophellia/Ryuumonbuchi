"""Server: catalog listing, tool dispatch, health.ping, response_format."""

from __future__ import annotations

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportUndefinedVariable=false
import asyncio
import contextlib
import json
import time
from pathlib import Path

from ryuumonbuchi import __version__
from ryuumonbuchi.catalog import TOOL_BY_NAME, TOOL_SPECS
from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.native import NativeResult, NativeRunner, NativeSpawnError
from ryuumonbuchi.process import PersistentWorker, WorkerCall
from ryuumonbuchi.server import (
    ServerState,
    _dispatch_tool,
    _error_result,
    _success_result,
    _summarize,
    _to_jsonable,
    create_server,
    main,
)
from ryuumonbuchi.session import RuntimeWorkspace


def _make_state(workspace: RuntimeWorkspace, fake_ghidra: Path) -> ServerState:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )
    worker = PersistentWorker(config=config, workspace=workspace)
    native = NativeRunner(config=config, workspace=workspace)
    return ServerState(config=config, workspace=workspace, worker=worker, native=native)


def test_create_server_returns_server(fake_ghidra: Path) -> None:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )
    server = create_server(config)
    assert server is not None
    assert server.name == "ryuumonbuchi"


def test_success_result_returns_two_content_blocks() -> None:
    result = _success_result("function.list", {"count": 5})
    assert len(result) == 2


def test_success_result_summary() -> None:
    result = _success_result("function.list", {"count": 5})
    assert "5" in result[0].text  # type: ignore[union-attr]


def test_error_result_has_code_prefix() -> None:
    result = _error_result("ghidra_error", "bad address")
    assert "ghidra_error" in result[0].text  # type: ignore[union-attr]
    assert "bad address" in result[0].text  # type: ignore[union-attr]


def test_error_result_with_log_tail() -> None:
    result = _error_result("worker_failed", "crash", log_tail="traceback")
    assert "traceback" in result[0].text  # type: ignore[union-attr]


def test_summarize_count() -> None:
    assert "5" in _summarize("function.list", {"count": 5})


def test_summarize_session_id() -> None:
    assert "s1" in _summarize("program.open", {"session_id": "s1"})


def test_summarize_keys() -> None:
    summary = _summarize("memory.read", {"address": "0x1000", "bytes_hex": "ab"})
    assert "memory.read" in summary


def test_summarize_non_dict() -> None:
    assert "str" in _summarize("test", "hello")


def test_to_jsonable_none() -> None:
    assert _to_jsonable(None) is None


def test_to_jsonable_primitives() -> None:
    assert _to_jsonable(42) == 42
    assert _to_jsonable("hello") == "hello"
    assert _to_jsonable(True) is True
    assert _to_jsonable(3.14) == 3.14


def test_to_jsonable_list() -> None:
    assert _to_jsonable([1, "a"]) == [1, "a"]


def test_to_jsonable_dict() -> None:
    assert _to_jsonable({"k": "v"}) == {"k": "v"}


def test_to_jsonable_object() -> None:
    class Foo:
        pass

    assert isinstance(_to_jsonable(Foo()), str)


def test_dispatch_unknown_tool(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "nonexistent.tool", {}))
    assert "invalid_params" in result[0].text  # type: ignore[union-attr]


def test_dispatch_health_ping(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "health.ping", {}))
    text = result[1].text if len(result) > 1 else result[0].text
    data = json.loads(text)  # type: ignore[arg-type]
    assert data["status"] == "ok"
    assert data["package_version"] == __version__


def test_dispatch_response_format(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "mcp.response_format", {}))
    assert len(result) >= 1


def test_main_callable() -> None:
    assert callable(main)


def test_all_tools_have_dispatch_path() -> None:
    assert "health.ping" in TOOL_BY_NAME
    assert "mcp.response_format" in TOOL_BY_NAME
    assert "headless.run" in TOOL_BY_NAME
    assert "headless.start" in TOOL_BY_NAME
    assert "operation.batch" in TOOL_BY_NAME
    backend_tools = [s for s in TOOL_SPECS if s.backend_method is not None]
    assert len(backend_tools) == 212


class _StubNative:
    """Stands in for NativeRunner: records argv, returns a canned result."""

    def __init__(self, *, delay: float = 0.0, error: Exception | None = None) -> None:
        self.delay = delay
        self.error = error
        self.terminated: list[object] = []
        self.progress_calls: list[tuple[float, float | None, str | None]] = []
        self.spawned = object()

    def run(self, **kwargs: object) -> NativeResult:
        on_spawn = kwargs.get("on_spawn")
        if callable(on_spawn):
            on_spawn(self.spawned)  # type: ignore[arg-type]
        progress = kwargs.get("progress")
        if callable(progress):
            progress(1.0, 30.0, None)  # type: ignore[call-arg]
            self.progress_calls.append((1.0, 30.0, None))
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return NativeResult(
            arguments=list(kwargs.get("arguments", [])),  # type: ignore[arg-type]
            working_directory=None,
            terminal=False,
            exit_code=0,
            duration_seconds=0.01,
            stdout="done",
            stderr="",
            terminal_output=None,
            stdout_path=None,
            stderr_path=None,
            terminal_output_path=None,
            stdout_truncated=False,
            stderr_truncated=False,
            terminal_output_truncated=False,
        )

    def _terminate_group(self, proc: object) -> None:
        self.terminated.append(proc)


class _StubWorker:
    """Stands in for PersistentWorker for the polled analysis path."""

    def __init__(self, statuses: list[dict[str, object]], result: dict[str, object]) -> None:
        self.statuses = statuses
        self.result = result
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call(self, tool: str, arguments: dict[str, object]) -> WorkerCall:
        self.calls.append((tool, arguments))
        if tool == "analysis.update":
            return WorkerCall(request_id="r", result={"task_id": "t1", "status": "running"})
        if tool == "task.status":
            return WorkerCall(request_id="r", result=self.statuses.pop(0))
        if tool == "task.result":
            return WorkerCall(request_id="r", result=self.result)
        return WorkerCall(request_id="r", result={"task_id": "t1"})


def _native_state(workspace: RuntimeWorkspace, fake_ghidra: Path, native: object) -> ServerState:
    state = _make_state(workspace, fake_ghidra)
    state.native = native  # type: ignore[assignment]
    return state


def test_headless_start_runs_and_reports_terminal_result(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    native = _StubNative()

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        started = json.loads(
            (await _dispatch_tool(state, "headless.start", {"arguments": ["-help"]}))[1].text
        )
        task_id = started["task_id"]
        assert task_id.startswith("native-")
        record = state.native_tasks[task_id]
        assert record.future is not None
        await record.future

        status = json.loads(
            (await _dispatch_tool(state, "task.status", {"task_id": task_id}))[1].text
        )
        assert status["status"] == "completed"
        assert status["result_ready"] is True
        assert status["kind"] == "headless.start"

        payload = json.loads(
            (await _dispatch_tool(state, "task.result", {"task_id": task_id}))[1].text
        )
        assert payload["status"] == "completed"
        assert payload["result"]["exit_code"] == 0
        assert payload["result"]["arguments"] == ["-help"]

    asyncio.run(_run())


def test_headless_start_records_failure(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    native = _StubNative(error=NativeSpawnError("launcher missing"))

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        started = json.loads(
            (await _dispatch_tool(state, "headless.start", {"arguments": []}))[1].text
        )
        record = state.native_tasks[started["task_id"]]
        assert record.future is not None
        with contextlib.suppress(NativeSpawnError):
            await record.future
        payload = json.loads(
            (await _dispatch_tool(state, "task.result", {"task_id": started["task_id"]}))[1].text
        )
        assert payload["status"] == "failed"
        assert "launcher missing" in payload["error"]

    asyncio.run(_run())


def test_native_task_result_rejects_running_task(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    native = _StubNative(delay=0.2)

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        started = json.loads(
            (await _dispatch_tool(state, "headless.start", {"arguments": []}))[1].text
        )
        task_id = started["task_id"]
        result = await _dispatch_tool(state, "task.result", {"task_id": task_id})
        assert "not in a terminal state" in result[0].text  # type: ignore[union-attr]
        record = state.native_tasks[task_id]
        assert record.future is not None
        await record.future

    asyncio.run(_run())


def test_native_task_cancel_terminates_process_group(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    native = _StubNative(delay=0.2)

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        started = json.loads(
            (await _dispatch_tool(state, "headless.start", {"arguments": []}))[1].text
        )
        task_id = started["task_id"]
        record = state.native_tasks[task_id]
        await asyncio.sleep(0.05)
        cancelled = json.loads(
            (await _dispatch_tool(state, "task.cancel", {"task_id": task_id}))[1].text
        )
        assert cancelled["cancel_requested"] is True
        assert native.terminated == [native.spawned]
        assert record.future is not None
        await record.future

    asyncio.run(_run())


def test_native_task_unknown_id(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "task.status", {"task_id": "native-missing"}))
    assert "unknown task" in result[0].text  # type: ignore[union-attr]


def test_analysis_update_and_wait_reports_progress(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    reported: list[tuple[float, float | None, str | None]] = []

    async def progress(current: float, total: float | None, message: str | None) -> None:
        reported.append((current, total, message))

    worker = _StubWorker(
        statuses=[
            {
                "status": "running",
                "progress": 3,
                "progress_max": 10,
                "progress_message": "Analyzing",
            },
            {"status": "completed", "progress": 10, "progress_max": 10},
        ],
        result={
            "status": "completed",
            "result": {"session_id": "s1", "status": "completed", "log": "ok"},
        },
    )

    async def _run() -> None:
        state = _make_state(workspace, fake_ghidra)
        state.worker = worker  # type: ignore[assignment]
        content = await _dispatch_tool(
            state, "analysis.update_and_wait", {"session_id": "s1"}, progress=progress
        )
        payload = json.loads(content[1].text)  # type: ignore[union-attr]
        assert payload == {"session_id": "s1", "status": "completed", "log": "ok"}

    asyncio.run(_run())
    # Elapsed-over-deadline: monitor counters restart per analyzer, so only the
    # phase message is forwarded from the monitor.
    assert reported[0][1] == 30.0
    assert reported[0][2] == "Analyzing"
    assert reported[1][2] is None
    assert reported[0][0] <= reported[1][0] <= 30.0
    assert [tool for tool, _ in worker.calls] == [
        "analysis.update",
        "task.status",
        "task.status",
        "task.result",
    ]


def test_analysis_update_and_wait_surfaces_task_failure(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    async def progress(current: float, total: float | None, message: str | None) -> None:
        return None

    worker = _StubWorker(
        statuses=[{"status": "failed"}],
        result={"status": "failed", "error": "analysis failed: boom"},
    )

    async def _run() -> None:
        state = _make_state(workspace, fake_ghidra)
        state.worker = worker  # type: ignore[assignment]
        content = await _dispatch_tool(
            state, "analysis.update_and_wait", {"session_id": "s1"}, progress=progress
        )
        assert "ghidra_error" in content[0].text  # type: ignore[union-attr]
        assert "boom" in content[0].text  # type: ignore[union-attr]

    asyncio.run(_run())


def test_analysis_update_and_wait_without_progress_uses_blocking_call(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    calls: list[str] = []

    class _Blocking:
        async def call(self, tool: str, arguments: dict[str, object]) -> WorkerCall:
            calls.append(tool)
            return WorkerCall(request_id="r", result={"session_id": "s1", "status": "completed"})

    async def _run() -> None:
        state = _make_state(workspace, fake_ghidra)
        state.worker = _Blocking()  # type: ignore[assignment]
        await _dispatch_tool(state, "analysis.update_and_wait", {"session_id": "s1"})

    asyncio.run(_run())
    assert calls == ["analysis.update_and_wait"]


def test_headless_run_forwards_progress(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    native = _StubNative()
    reported: list[tuple[float, float | None, str | None]] = []

    async def progress(current: float, total: float | None, message: str | None) -> None:
        reported.append((current, total, message))

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        content = await _dispatch_tool(
            state, "headless.run", {"arguments": ["-help"]}, progress=progress
        )
        payload = json.loads(content[1].text)  # type: ignore[union-attr]
        assert payload["exit_code"] == 0

    asyncio.run(_run())
    assert reported == [(1.0, 30.0, None)]


def test_headless_run_without_progress_skips_forwarding(
    workspace: RuntimeWorkspace, fake_ghidra: Path
) -> None:
    native = _StubNative()

    async def _run() -> None:
        state = _native_state(workspace, fake_ghidra, native)
        content = await _dispatch_tool(state, "headless.run", {"arguments": []})
        payload = json.loads(content[1].text)  # type: ignore[union-attr]
        assert payload["exit_code"] == 0

    asyncio.run(_run())
    assert native.progress_calls == []
