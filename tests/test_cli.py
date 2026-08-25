"""CLI: argument parsing, version, config building."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import pytest

from ryuumonbuchi.cli import _parser, main


def test_parser_version_flag() -> None:
    parser = _parser()
    args = parser.parse_args(["--version"])
    assert args.version is True


def test_parser_has_classpath_arg() -> None:
    parser = _parser()
    args = parser.parse_args(["--classpath", "/lib1", "--classpath", "/lib2"])
    assert args.classpath == ["/lib1", "/lib2"]


def test_parser_has_class_file_arg() -> None:
    parser = _parser()
    args = parser.parse_args(["--class-file", "/Test.class"])
    assert args.class_file == ["/Test.class"]


def test_parser_has_vmarg_arg() -> None:
    parser = _parser()
    args = parser.parse_args(["--vmarg=-Dfoo=bar", "--vmarg=-Dbaz=qux"])
    assert args.vmarg == ["-Dfoo=bar", "-Dbaz=qux"]


def test_parser_has_max_import_bytes() -> None:
    parser = _parser()
    args = parser.parse_args(["--max-import-bytes", "1024"])
    assert args.max_import_bytes == 1024


def test_parser_has_max_response_bytes() -> None:
    parser = _parser()
    args = parser.parse_args(["--max-response-bytes", "2048"])
    assert args.max_response_bytes == 2048


def test_parser_has_max_log_tail_bytes() -> None:
    parser = _parser()
    args = parser.parse_args(["--max-log-tail-bytes", "512"])
    assert args.max_log_tail_bytes == 512


def test_parser_no_args_defaults() -> None:
    parser = _parser()
    args = parser.parse_args([])
    assert args.version is False
    assert args.classpath == []
    assert args.class_file == []
    assert args.vmarg == []


def test_main_version_prints(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--version"])
    captured = capsys.readouterr()
    assert "0.3.0" in captured.out


def test_main_invalid_config_exits(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/nonexistent/path")
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 2


def test_main_module_entrypoint(capsys: pytest.CaptureFixture[str]) -> None:
    from ryuumonbuchi.__main__ import main as module_main

    module_main(["--version"])
    captured = capsys.readouterr()
    assert "0.3.0" in captured.out
