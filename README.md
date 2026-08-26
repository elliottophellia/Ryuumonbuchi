<div align="center">

<img src="https://cdn.rei.my.id/images/Ryuumonbuchi.png?v=1.0.0" alt="Ryuumonbuchi" />

# Ryuumonbuchi

**Maybe the headless Ghidra MCP you are looking for.**

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue?style=flat-square)](LICENSE)
[![Ghidra](https://img.shields.io/badge/Ghidra-headless-FF6600?style=flat-square)](https://ghidra-sre.org)
[![MCP](https://img.shields.io/badge/Protocol-MCP-6E4AF0?style=flat-square)](https://modelcontextprotocol.io)

A 216-tool [Model Context Protocol](https://modelcontextprotocol.io) server that exposes a [Ghidra](https://ghidra-sre.org) reverse-engineering surface to LLM agents. Runs on Linux and Python 3.13, speaks MCP over stdio, and drives one persistent PyGhidra/JVM backend per connection.

[Overview](#overview) &middot; [Architecture](#architecture) &middot; [Prerequisites](#prerequisites) &middot; [Install](#install) &middot; [Configuration](#configuration) &middot; [Tool surface](#tool-surface) &middot; [Usage](#usage) &middot; [Development](#development)

</div>

## Overview

Ryuumonbuchi turns Ghidra into an MCP tool server. An agent connects over stdio, opens a binary, and drives analysis through typed tool calls: decompilation, disassembly, type reconstruction, patching, symbol and memory edits, and project export. No GUI automation, no hand-written `analyzeHeadless` scripts.

The server uses the low-level MCP SDK (`mcp.server.lowlevel`) with a registry generated from one authoritative catalog. The catalog declares 216 dotted tool names. 212 of them map one-to-one onto methods of a persistent backend; `health.ping` and `mcp.response_format` are server-native, `headless.run` is the native launcher path, and `operation.batch` is the batching dispatcher. The catalog does not promise coverage of every Ghidra API; it covers the surface those 212 methods implement.

Behind the stdio front end, one persistent worker child holds a live PyGhidra/JVM session for the whole MCP lifespan. Repeated calls reuse the warmed backend instead of paying JVM startup per request.

## Architecture

```
 MCP client ── stdio (JSON-RPC) ──► Ryuumonbuchi server
                                   (low-level SDK, schema/policy dispatch)
                                              │
                                              │ protocol-v2, 8-byte length-prefixed socket IPC
                                              ▼
                                   persistent worker child
                                   (lazy PyGhidra/JVM, multiple program sessions)
                                              │
                           ┌──────────────────┴───────────────────┐
                           ▼                                      ▼
                   backend (PyGhidra)              headless.run ── analyzeHeadless
                   program sessions,                (separate process group)
                   decompiler, analysis
```

Three dispatch paths:

1. Worker tools (212): validated against the catalog schema, sent to the persistent child over protocol-v2 IPC, run against a live program session.
2. `headless.run`: spawns `support/analyzeHeadless` directly with the caller's argv in its own process group. No shell, no rewriting of arguments.
3. `operation.batch`: 1 to 32 worker tools in one call; read-only batches run without a transaction, mutating batches wrap in one undo transaction with rollback on error.

The private mode-0700 workspace owns every managed Ghidra project, worker log file, and native capture file. Oversized worker results spill to mode-0600 files under the workspace and are reloaded internally; they are not surfaced to the MCP client as a path contract.

## Prerequisites

- Linux host.
- Python `>=3.13,<3.14`.
- Ghidra 12.0 or newer, with metadata declaring a Java minimum of 21 (`application.java.min`) and Python 3.13 support (`application.python.supported`). Ghidra bundles its own JDK, so no separate Java install is required when it is present.
- [uv](https://docs.astral.sh/uv/) for the documented workflow.

Startup validates the installation before entering the MCP loop. It checks `Ghidra/application.properties`, `Ghidra/Features/PyGhidra/lib/PyGhidra.jar`, and `support/analyzeHeadless`, then exits with code 2 on any configuration failure.

## Install

Run the published package from PyPI:

```bash
uvx ryuumonbuchi
```

`uvx` builds an isolated environment on first run and reuses it after.

To run the current main branch instead:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi@main ryuumonbuchi
```

For a local checkout:

```bash
git clone https://github.com/elliottophellia/Ryuumonbuchi.git
cd ryuumonbuchi
uv sync --locked --all-groups
uv run ryuumonbuchi
```

## Configuration

Precedence is CLI flag over environment variable over built-in default. Classpath, class-file, and VM-argument values from CLI and environment are combined rather than overridden.

| CLI flag | Environment variable | Default | Description |
|---|---|---|---|
| `--ghidra-install-dir PATH` | `GHIDRA_INSTALL_DIR` | `/usr/share/ghidra` | Ghidra installation root |
| `--max-heap-mb MIB` | `RYUUMONBUCHI_MAX_HEAP_MB` | `1024` | Worker JVM max heap, 256 to 8192 |
| `--max-cpu COUNT` | `RYUUMONBUCHI_MAX_CPU` | `2` | Worker CPU affinity count, 1 to `os.cpu_count()` |
| `--operation-timeout-seconds SECONDS` | `RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS` | `900` | Per-operation wall-clock deadline, 30 to 86400 |
| `--max-import-bytes BYTES` | `RYUUMONBUCHI_MAX_IMPORT_BYTES` | `67108864` | Cap on `program.open_bytes` payloads |
| `--max-response-bytes BYTES` | `RYUUMONBUCHI_MAX_RESPONSE_BYTES` | `4194304` | Inline response cap before spill-to-file |
| `--max-log-tail-bytes BYTES` | `RYUUMONBUCHI_MAX_LOG_TAIL_BYTES` | `65536` | Worker log tail returned on failure |
| `--classpath PATH` (repeatable) | `RYUUMONBUCHI_CLASSPATH` (path-separated) | empty | Extra Java classpath entries |
| `--class-file PATH` (repeatable) | `RYUUMONBUCHI_CLASS_FILES` (path-separated) | empty | Extra Java class files to load |
| `--vmarg ARG` (repeatable) | `RYUUMONBUCHI_VMARGS` (shlex) | empty | Extra JVM arguments |
| `--allow-export` | `RYUUMONBUCHI_ALLOW_EXPORT` | disabled | Enable export and save tools |
| `--allow-import-bytes` | `RYUUMONBUCHI_ALLOW_IMPORT_BYTES` | disabled | Enable `program.open_bytes` |

> [!IMPORTANT]
> `program.export_binary`, `program.export_packed`, `program.save`, `program.save_as`, and `project.export` require `RYUUMONBUCHI_ALLOW_EXPORT=1` or `--allow-export`. `program.open_bytes` requires `RYUUMONBUCHI_ALLOW_IMPORT_BYTES=1` or `--allow-import-bytes`, and obeys the byte cap. Both gates default to deny.

## Tool surface

All 216 tools use dotted names and take a JSON object. Backend tools generally accept a `session_id` (returned by `program.open` or `program.open_bytes`) and are batch-eligible. A representative slice, drawn from the catalog:

| Category | Example tools |
|---|---|
| Program & session | `program.open`, `program.open_bytes`, `program.close`, `program.summary`, `program.report`, `program.mode.get/set`, `program.image_base.set`, `program.save`, `program.save_as`, `program.export_binary`, `program.export_packed` |
| Analysis & tasks | `analysis.update`, `analysis.update_and_wait`, `analysis.status`, `analysis.options.*`, `analysis.analyzers.*`, `analysis.clear_cache`, `task.analysis_update`, `task.status`, `task.result`, `task.cancel` |
| Listing, decompilation, p-code | `listing.disassemble.*`, `listing.code_units.list`, `listing.data.*`, `listing.clear`, `decomp.function`, `decomp.tokens`, `decomp.ast`, `decomp.writeback.*`, `pcode.function`, `pcode.block`, `pcode.op.at` |
| Functions, symbols, types, layouts | `function.*`, `symbol.*`, `namespace.create`, `class.create`, `type.*`, `layout.struct.*`, `layout.enum.*`, `layout.union.*`, `variable.*`, `parameter.*` |
| References, search, graphs | `reference.*`, `search.*`, `graph.basic_blocks`, `graph.cfg.edges`, `graph.call_paths` |
| Memory | `memory.blocks.list`, `memory.read`, `memory.write`, `memory.block.*` |
| Comments, bookmarks, tags | `comment.*`, `bookmark.*`, `tag.*` |
| Transactions & patches | `transaction.*`, `patch.assemble`, `patch.nop`, `patch.branch_invert` |
| Projects & metadata | `project.*`, `metadata.query`, `metadata.store` |
| External, source, relocations | `external.*`, `source.file.*`, `source.map.*`, `relocation.*`, `equate.*` |
| Open world | `ghidra.call`, `ghidra.eval`, `ghidra.script` |
| Server-native | `health.ping`, `mcp.response_format`, `headless.run`, `operation.batch` |

## Usage

A first-analysis sequence:

1. `health.ping`: confirm the server responds; this never starts the JVM.
2. `program.open` with `path`, `read_only: true`, `update_analysis: false`. Both `read_only` and `update_analysis` default to `true` when omitted, so set `update_analysis: false` when analysis options must be changed first.
3. `analysis.update_and_wait` to run auto-analysis to completion.
4. `function.list` to enumerate recovered functions.
5. `decomp.function` on a function start address.
6. `program.close`.

### Function addresses and decompiler views

Function tools accept exact function entries and addresses contained within a function. An unresolved address remains an error rather than selecting a nearby function; the error reports the normalized address plus the nearest previous and next function entries.

`decomp.function` defaults to `view: "raw"`, the complete Ghidra C output. Use `view: "compact"` only for initial triage of declaration-heavy functions:

```json
{
  "session_id": "<session_id>",
  "function_start": 1053104,
  "view": "compact"
}
```

Compact output conservatively elides Ghidra-generated local declarations, is not compilable, and reports the omission count. Return to raw C, `decomp.tokens`, `decomp.ast`, or p-code when exact structure matters.

Typed tools come first. Sessions open read-only by default; switch `program.mode.set` to `read_only: false` only before intended mutations. Use `operation.batch` for 1 to 32 atomic program-bound calls. Treat `ghidra.call`, `ghidra.eval`, `ghidra.script`, and `headless.run` as open-world execution. Inspect the second `TextContent` block for the full JSON result; the first is a compact summary. Close sessions with `program.close` when done.

### Claude Code

Add the server under `mcpServers` in `.mcp.json` or `~/.claude.json`:

```json
{
  "mcpServers": {
    "ryuumonbuchi": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "ryuumonbuchi",
        "--ghidra-install-dir",
        "/usr/share/ghidra"
      ],
      "env": {
        "RYUUMONBUCHI_MAX_CPU": "4",
        "RYUUMONBUCHI_MAX_HEAP_MB": "2048"
      }
    }
  }
}
```

### Codex

Add the server to `~/.codex/config.toml`:

```toml
[mcp_servers.ryuumonbuchi]
command = "uvx"
args = ["ryuumonbuchi", "--ghidra-install-dir", "/usr/share/ghidra"]
[mcp_servers.ryuumonbuchi.env]
RYUUMONBUCHI_MAX_CPU = "4"
RYUUMONBUCHI_MAX_HEAP_MB = "2048"
```

## Development

```bash
uv sync --locked --all-groups     # install runtime and dev dependencies
uv run ryuumonbuchi --version     # print version and exit
uv run ryuumonbuchi --help        # list every CLI flag
```

Test tiers:

```bash
uv run pytest tests/test_mcp_client_smoke.py tests/test_worker_lifecycle.py -q
uv run pytest -m "not live and not live_server" --cov=ryuumonbuchi --cov-branch --cov-report=term-missing --cov-fail-under=100
```

The live matrix requires a real Ghidra install plus Java 21 and a C compiler, and is skipped by default:

```bash
RYUUMONBUCHI_REQUIRE_LIVE=1 GHIDRA_INSTALL_DIR=/usr/share/ghidra uv run pytest -m live tests/test_live_workflow.py -q
```

Static checks run with `ruff check`, `ruff format --check`, and strict `pyright`.