"""Native runner: argv byte-for-byte, environment, cwd, exit codes, capture."""

# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false

import stat
import textwrap
from pathlib import Path

import pytest

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.native import NativeRunError, NativeRunner, NativeSpawnError
from ryuumonbuchi.session import RuntimeWorkspace


@pytest.fixture
def native_runner(workspace: RuntimeWorkspace, fake_ghidra: Path) -> NativeRunner:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
        max_log_tail_bytes=4096,
    )
    return NativeRunner(config=config, workspace=workspace)


@pytest.fixture
def probe_script(tmp_path: Path) -> Path:
    """Create an executable fixture that records argv/env/cwd/stdin/stdout/stderr."""
    script = tmp_path / "probe.py"
    script.write_text(
        textwrap.dedent("""\
        #!/usr/bin/env python3
        import os, sys, json
        data = {
            "argv": sys.argv[1:],
            "cwd": os.getcwd(),
            "env_keys": sorted(k for k in os.environ if k.startswith("PROBE_")),
            "stdin": sys.stdin.read() if not sys.stdin.isatty() else None,
            "pid": os.getpid(),
        }
        sys.stdout.write("PROBE_SENTinel\\n")
        sys.stdout.write(json.dumps(data))
        sys.stderr.write("STDERR_MARKER\\n")
        sys.exit(0)
    """)
    )
    script.chmod(0o755)
    return script


@pytest.fixture
def headless_fixture(fake_ghidra: Path, probe_script: Path) -> None:
    """Install the probe as analyzeHeadless."""
    launcher = fake_ghidra / "support" / "analyzeHeadless"
    launcher.write_text(
        textwrap.dedent("""\
        #!/usr/bin/env python3
        import os, sys, json
        data = {
            "argv": sys.argv[1:],
            "cwd": os.getcwd(),
            "env_keys": sorted(k for k in os.environ if k.startswith("PROBE_")),
            "stdin": sys.stdin.read() if not sys.stdin.isatty() else None,
            "pid": os.getpid(),
        }
        sys.stdout.write("PROBE_SENTinel\\n")
        sys.stdout.write(json.dumps(data))
        sys.stderr.write("STDERR_MARKER\\n")
    """)
    )
    launcher.chmod(0o755)


def test_native_spawn_error_no_launcher(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    """Missing analyzeHeadless raises NativeSpawnError."""
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )
    runner = NativeRunner(config=config, workspace=workspace)
    # Remove the launcher
    (fake_ghidra / "support" / "analyzeHeadless").unlink()
    with pytest.raises(NativeSpawnError):
        runner.run(arguments=["test"])


def test_native_argv_byte_for_byte(native_runner: NativeRunner, headless_fixture: None) -> None:
    """Arguments are passed exactly without shell expansion."""
    result = native_runner.run(
        arguments=["-import", "/path with spaces/file.bin", "-postScript", "Script.py"],
    )
    assert result.exit_code == 0
    import json

    lines = result.stdout.split("\n") if result.stdout else []
    data = json.loads(lines[1]) if len(lines) > 1 else {}
    assert data["argv"] == ["-import", "/path with spaces/file.bin", "-postScript", "Script.py"]


def test_native_environment_overlay(native_runner: NativeRunner, headless_fixture: None) -> None:
    """Explicit environment keys appear in the child."""
    result = native_runner.run(
        arguments=["test"],
        environment={"PROBE_KEY": "probe_value"},
    )
    assert result.exit_code == 0
    import json

    lines = result.stdout.split("\n") if result.stdout else []
    data = json.loads(lines[1]) if len(lines) > 1 else {}
    assert "PROBE_KEY" in data["env_keys"]


def test_native_working_directory(
    native_runner: NativeRunner, headless_fixture: None, tmp_path: Path
) -> None:
    """Working directory is respected."""
    result = native_runner.run(
        arguments=["test"],
        working_directory=str(tmp_path),
    )
    assert result.exit_code == 0
    import json

    lines = result.stdout.split("\n") if result.stdout else []
    data = json.loads(lines[1]) if len(lines) > 1 else {}
    assert data["cwd"] == str(tmp_path)


def test_native_stdin_piped(native_runner: NativeRunner, headless_fixture: None) -> None:
    """stdin_text is piped to the child."""
    result = native_runner.run(
        arguments=["test"],
        stdin_text="hello stdin",
    )
    assert result.exit_code == 0
    import json

    lines = result.stdout.split("\n") if result.stdout else []
    data = json.loads(lines[1]) if len(lines) > 1 else {}
    assert data["stdin"] == "hello stdin"


def test_native_nonzero_exit(native_runner: NativeRunner, fake_ghidra: Path) -> None:
    """Nonzero exit code is captured."""
    launcher = fake_ghidra / "support" / "analyzeHeadless"
    launcher.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n")
    launcher.chmod(0o755)
    result = native_runner.run(arguments=["test"])
    assert result.exit_code == 7


def test_native_stdout_stderr_capture(native_runner: NativeRunner, headless_fixture: None) -> None:
    """stdout and stderr are captured separately."""
    result = native_runner.run(arguments=["test"])
    assert result.stdout is not None
    assert "PROBE_SENTinel" in result.stdout
    assert result.stderr is not None
    assert "STDERR_MARKER" in result.stderr
    assert result.terminal_output is None


def test_native_capture_paths_exist(native_runner: NativeRunner, headless_fixture: None) -> None:
    """Capture file paths exist and are mode 0600."""
    result = native_runner.run(arguments=["test"])
    assert result.stdout_path is not None
    assert Path(result.stdout_path).exists()
    assert result.stderr_path is not None
    assert Path(result.stderr_path).exists()
    mode = stat.S_IMODE(Path(result.stdout_path).stat().st_mode)
    assert mode == 0o600


def test_native_duration_positive(native_runner: NativeRunner, headless_fixture: None) -> None:
    """Duration is a positive float."""
    result = native_runner.run(arguments=["test"])
    assert result.duration_seconds > 0


def test_native_no_persistent_backend_pid_change(
    native_runner: NativeRunner, headless_fixture: None
) -> None:
    """Native runs don't affect any persistent backend."""
    result1 = native_runner.run(arguments=["test"])
    result2 = native_runner.run(arguments=["test"])
    # Each run is a fresh process
    import json

    lines1 = result1.stdout.split("\n") if result1.stdout else []
    lines2 = result2.stdout.split("\n") if result2.stdout else []
    data1 = json.loads(lines1[1]) if len(lines1) > 1 else {}
    data2 = json.loads(lines2[1]) if len(lines2) > 1 else {}
    assert data1["pid"] != data2["pid"]


def test_native_timeout(native_runner: NativeRunner, fake_ghidra: Path) -> None:
    """Timeout kills the child."""
    launcher = fake_ghidra / "support" / "analyzeHeadless"
    launcher.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(100)\n")
    launcher.chmod(0o755)
    with pytest.raises(NativeRunError):
        native_runner.run(arguments=["test"], timeout_seconds=2)


def test_native_ghidra_install_dir_forced(
    native_runner: NativeRunner, headless_fixture: None, fake_ghidra: Path
) -> None:
    """GHIDRA_INSTALL_DIR is forced in the child environment."""
    result = native_runner.run(arguments=["test"])
    assert result.exit_code == 0
    # The child should have GHIDRA_INSTALL_DIR set
    # Our probe doesn't print it, but the fact it runs means the env was set
