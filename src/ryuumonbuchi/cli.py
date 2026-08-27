"""Command-line entrypoint with fail-fast Ghidra validation."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import ConfigError, build_config, validate_config
from .server import main as run_server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ryuumonbuchi",
        description="Headless Ghidra MCP server with persistent worker isolation.",
    )
    parser.add_argument("--ghidra-install-dir", metavar="PATH")
    parser.add_argument("--max-heap-mb", type=int, metavar="MIB")
    parser.add_argument("--max-cpu", type=int, metavar="COUNT")
    parser.add_argument("--operation-timeout-seconds", type=int, metavar="SECONDS")
    parser.add_argument("--max-import-bytes", type=int, metavar="BYTES")
    parser.add_argument("--max-response-bytes", type=int, metavar="BYTES")
    parser.add_argument("--max-log-tail-bytes", type=int, metavar="BYTES")
    parser.add_argument(
        "--classpath",
        action="append",
        default=[],
        metavar="PATH",
        help="additional Java classpath entry (repeatable)",
    )
    parser.add_argument(
        "--class-file",
        action="append",
        default=[],
        metavar="PATH",
        help="additional Java class file to load (repeatable)",
    )
    parser.add_argument(
        "--allow-export",
        action="store_true",
        default=None,
        help="enable filesystem export/save tools (default: deny)",
    )
    parser.add_argument(
        "--allow-import-bytes",
        action="store_true",
        default=None,
        help="enable program.open_bytes byte import (default: deny)",
    )
    parser.add_argument(
        "--vmarg",
        action="append",
        default=[],
        metavar="ARG",
        help="additional JVM argument (repeatable)",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        help="MCP transport to serve (default: stdio)",
    )
    parser.add_argument(
        "--http-host",
        metavar="HOST",
        help="bind address for --transport http (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        metavar="PORT",
        help="bind port for --transport http (default: 8765)",
    )
    parser.add_argument(
        "--http-path",
        metavar="PATH",
        help="streamable HTTP mount path (default: /mcp)",
    )
    parser.add_argument("--version", action="store_true", help="print the package version and exit")
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse options, validate Ghidra, then serve MCP over the configured transport."""

    args = _parser().parse_args(argv)
    if args.version:
        print(__version__)
        return
    try:
        config = build_config(
            ghidra_install_dir=args.ghidra_install_dir,
            max_heap_mb=args.max_heap_mb,
            max_cpu=args.max_cpu,
            operation_timeout_seconds=args.operation_timeout_seconds,
            max_import_bytes=args.max_import_bytes,
            max_response_bytes=args.max_response_bytes,
            max_log_tail_bytes=args.max_log_tail_bytes,
            classpaths=args.classpath or None,
            class_files=args.class_file or None,
            vm_args=args.vmarg or None,
            allow_export=args.allow_export,
            allow_import_bytes=args.allow_import_bytes,
            transport=args.transport,
            http_host=args.http_host,
            http_port=args.http_port,
            http_path=args.http_path,
        )
        validate_config(config)
        run_server(config)
    except (ConfigError, FileNotFoundError) as exc:
        print(f"ryuumonbuchi: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
