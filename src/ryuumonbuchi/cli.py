# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

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
        description="Headless Ghidra MCP server with one-shot worker isolation.",
    )
    parser.add_argument("--ghidra-install-dir", metavar="PATH")
    parser.add_argument("--max-heap-mb", type=int, metavar="MIB")
    parser.add_argument("--max-cpu", type=int, metavar="COUNT")
    parser.add_argument("--operation-timeout-seconds", type=int, metavar="SECONDS")
    parser.add_argument("--version", action="store_true", help="print the package version and exit")
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse options, validate Ghidra, then start MCP stdio."""

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
        )
        validate_config(config)
        run_server(config)
    except (ConfigError, FileNotFoundError) as exc:
        print(f"ryuumonbuchi: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
