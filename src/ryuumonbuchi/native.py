"""Exact native analyzeHeadless execution for every target mode."""

from __future__ import annotations

import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import AppConfig
from .session import RuntimeWorkspace

# Keys inherited from parent environment
_INHERITED_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "HOME",
    "JAVA_HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "PYTHONPATH",
    "GHIDRA_INSTALL_DIR",
)

# Maximum inline output per stream before truncation
_MAX_INLINE_OUTPUT = 1 * 1024 * 1024  # 1 MiB

# Hard bound on the SIGTERM -> SIGKILL escalation.
_KILL_GRACE_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class NativeResult:
    """Result of one headless.run invocation."""

    arguments: list[str]
    working_directory: str | None
    terminal: bool
    exit_code: int
    duration_seconds: float
    stdout: str | None
    stderr: str | None
    terminal_output: str | None
    stdout_path: str | None
    stderr_path: str | None
    terminal_output_path: str | None
    stdout_truncated: bool
    stderr_truncated: bool
    terminal_output_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "arguments": self.arguments,
            "working_directory": self.working_directory,
            "terminal": self.terminal,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "terminal_output": self.terminal_output,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "terminal_output_path": self.terminal_output_path,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "terminal_output_truncated": self.terminal_output_truncated,
        }


class NativeRunError(RuntimeError):
    """Raised when a native headless run fails."""


class NativeSpawnError(NativeRunError):
    """Raised when the analyzeHeadless launcher cannot be found or started."""

    def __init__(self, message: str, *, code: str = "native_spawn_failed") -> None:
        super().__init__(message)
        self.code = code


class NativeTimeoutError(NativeRunError):
    """Raised when a native headless run exceeds its deadline."""


@dataclass(slots=True)
class NativeRunner:
    """Execute analyzeHeadless with exact argv, no shell, no normalization."""

    config: AppConfig
    workspace: RuntimeWorkspace

    def run(
        self,
        *,
        arguments: list[str],
        working_directory: str | None = None,
        environment: dict[str, str] | None = None,
        stdin_text: str | None = None,
        terminal: bool = False,
        timeout_seconds: int | None = None,
    ) -> NativeResult:
        """Invoke analyzeHeadless directly and capture complete output."""
        ghidra_dir = str(self.config.ghidra_install_dir)
        launcher = Path(ghidra_dir) / "support" / "analyzeHeadless"
        if not launcher.exists():
            msg = f"analyzeHeadless not found at {launcher}"
            raise NativeSpawnError(msg)

        argv = [str(launcher)] + list(arguments)

        env: dict[str, str] = {}
        for key in _INHERITED_ENV_KEYS:
            val = os.environ.get(key)
            if val is not None:
                env[key] = val
        if environment:
            env.update(environment)
        env["GHIDRA_INSTALL_DIR"] = ghidra_dir

        cwd = working_directory or str(Path.cwd())

        timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else self.config.operation_timeout_seconds
        )

        stdout_path = self.workspace.new_run_file(prefix="native-stdout-", suffix=".log")
        stderr_path = self.workspace.new_run_file(prefix="native-stderr-", suffix=".log")
        terminal_path: Path | None = None
        if terminal:
            terminal_path = self.workspace.new_run_file(prefix="native-terminal-", suffix=".log")

        start_time = time.monotonic()
        try:
            if terminal:
                if terminal_path is None:
                    message = "terminal capture path unavailable"
                    raise NativeSpawnError(message)
                returncode = self._run_terminal(
                    argv, env, cwd, stdin_text, terminal_path, timeout_seconds
                )
            else:
                returncode = self._run_piped(
                    argv, env, cwd, stdin_text, stdout_path, stderr_path, timeout_seconds
                )
        except NativeRunError:
            raise
        except OSError as exc:
            message = f"failed to start analyzeHeadless: {exc}"
            raise NativeSpawnError(message) from exc

        elapsed = time.monotonic() - start_time

        stdout_content, stdout_trunc = self._read_capture(stdout_path if not terminal else None)
        stderr_content, stderr_trunc = self._read_capture(stderr_path if not terminal else None)
        terminal_content, terminal_trunc = self._read_capture(terminal_path)

        return NativeResult(
            arguments=list(arguments),
            working_directory=working_directory,
            terminal=terminal,
            exit_code=returncode,
            duration_seconds=round(elapsed, 3),
            stdout=stdout_content,
            stderr=stderr_content,
            terminal_output=terminal_content,
            stdout_path=str(stdout_path) if not terminal else None,
            stderr_path=str(stderr_path) if not terminal else None,
            terminal_output_path=str(terminal_path) if terminal_path else None,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            terminal_output_truncated=terminal_trunc,
        )

    def _launch(
        self,
        argv: list[str],
        env: dict[str, str],
        cwd: str,
        *,
        stdin_target: int | None,
        stdout_target: int | None,
        stderr_target: int | None,
    ) -> subprocess.Popen[bytes]:
        """Spawn analyzeHeadless in its own session/process group."""
        return subprocess.Popen(  # noqa: S603
            argv,
            env=env,
            cwd=cwd,
            stdin=stdin_target if stdin_target is not None else subprocess.PIPE,
            stdout=stdout_target if stdout_target is not None else subprocess.PIPE,
            stderr=stderr_target if stderr_target is not None else subprocess.PIPE,
            start_new_session=True,
        )

    def _terminate_group(self, proc: subprocess.Popen[bytes] | None) -> None:
        """Send TERM then KILL to the process group and reap the leader."""
        from contextlib import suppress

        if proc is None:
            return
        if proc.poll() is not None:
            return
        with suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            with suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=_KILL_GRACE_SECONDS)

    @staticmethod
    def _close_fd(fd: int) -> None:
        from contextlib import suppress

        if fd >= 0:
            with suppress(OSError):
                os.close(fd)

    def _run_piped(
        self,
        argv: list[str],
        env: dict[str, str],
        cwd: str,
        stdin_text: str | None,
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: int,
    ) -> int:
        stdin_data = stdin_text.encode("utf-8") if stdin_text is not None else None

        stdout_fd = os.open(str(stdout_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        stderr_fd = os.open(str(stderr_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        proc: subprocess.Popen[bytes] | None = None
        deadline = time.monotonic() + timeout_seconds
        try:
            proc = self._launch(
                argv,
                env,
                cwd,
                stdin_target=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                stdout_target=stdout_fd,
                stderr_target=stderr_fd,
            )
            if stdin_data is not None and proc.stdin is not None:
                proc.stdin.write(stdin_data)
                proc.stdin.close()

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    message = f"native headless run timed out after {timeout_seconds}s"
                    raise NativeTimeoutError(message)
                try:
                    proc.wait(timeout=min(remaining, 1.0))
                except subprocess.TimeoutExpired:
                    continue
                return proc.returncode
        except NativeTimeoutError:
            self._terminate_group(proc)
            raise

    def _run_terminal(
        self,
        argv: list[str],
        env: dict[str, str],
        cwd: str,
        stdin_text: str | None,
        terminal_path: Path,
        timeout_seconds: int,
    ) -> int:
        import pty

        master_fd, slave_fd = pty.openpty()
        proc: subprocess.Popen[bytes] | None = None
        deadline = time.monotonic() + timeout_seconds
        try:
            with terminal_path.open("wb") as term_f:
                proc = self._launch(
                    argv,
                    env,
                    cwd,
                    stdin_target=subprocess.PIPE if stdin_text is not None else slave_fd,
                    stdout_target=slave_fd,
                    stderr_target=slave_fd,
                )
                self._close_fd(slave_fd)
                slave_fd = -1

                if stdin_text is not None and proc.stdin is not None:
                    proc.stdin.write(stdin_text.encode("utf-8"))
                    proc.stdin.close()

                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        message = f"native headless run timed out after {timeout_seconds}s"
                        raise NativeTimeoutError(message)
                    ready, _, _ = select.select([master_fd], [], [], min(remaining, 1.0))
                    if master_fd in ready:
                        try:
                            data = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        term_f.write(data)
                    if proc.poll() is not None and not ready:
                        break

                proc.wait(timeout=deadline - time.monotonic())
                return proc.returncode
        except NativeTimeoutError:
            self._terminate_group(proc)
            raise
        except (OSError, ValueError):
            self._terminate_group(proc)
            message = "native terminal read failed"
            raise NativeRunError(message) from None
        finally:
            self._close_fd(slave_fd)
            self._close_fd(master_fd)

    def _read_capture(self, path: Path | None) -> tuple[str | None, bool]:
        """Read a capture file, truncating to max_log_tail_bytes inline."""
        if path is None:
            return None, False
        try:
            raw = path.read_bytes()
        except OSError:
            return None, False
        total = len(raw)
        max_inline = min(self.config.max_log_tail_bytes, _MAX_INLINE_OUTPUT)
        truncated = total > max_inline
        if truncated:
            raw = raw[-max_inline:]
        try:
            text = raw.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, ValueError):
            text = raw.decode("latin-1", errors="replace")
        return text, truncated
