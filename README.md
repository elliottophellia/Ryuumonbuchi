<div align="center">

# Ryuumonbuchi

**Maybe the headless Ghidra MCP you are looking for.**

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue?style=flat-square)](LICENSE)
[![Ghidra](https://img.shields.io/badge/Ghidra-headless-FF6600?style=flat-square)](https://ghidra-sre.org)
[![MCP](https://img.shields.io/badge/Protocol-MCP-6E4AF0?style=flat-square)](https://modelcontextprotocol.io)

A 216-tool [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the full [Ghidra](https://ghidra-sre.org) reverse-engineering surface to LLM agents &mdash; decompilation, disassembly, type recovery, patching, scripting, and more &mdash; through a persistent, isolated worker process.

[Overview](#overview) &middot; [Architecture](#architecture) &middot; [Install](#install) &middot; [Configuration](#configuration) &middot; [Tool surface](#tool-surface) &middot; [Usage](#usage)

</div>

## Overview

Ryuumonbuchi turns Ghidra into an MCP tool server. An LLM agent connects over stdio, opens a binary, and drives every stage of static analysis &mdash; from auto-analysis and decompilation to struct reconstruction, patching, and project export &mdash; through typed tool calls instead of screen-scraping the Ghidra GUI or hand-rolling analyzeHeadless scripts.

It speaks the **low-level MCP SDK** (`mcp.server.lowlevel`) with a dynamic 216-tool registry generated from a single authoritative catalog. Behind the MCP front-end, a **persistent worker child** holds one live PyGhidra/JVM session for the entire MCP lifespan, so repeated calls reuse the warmed-up backend instead of paying JVM startup on every request.

### Highlights

- **216 tools** spanning program/session management, analysis, listing, decompilation, p-code, functions, symbols, memory, types, references, search, graphs, comments, bookmarks, tags, patches, transactions, tasks, external libraries, source maps, equates, and projects.
- **Persistent isolated worker** &mdash; one private PyGhidra process per MCP connection, reused across calls, torn down on disconnect.
- **Atomic batches** &mdash; 1&ndash;32 program-bound operations in a single transaction with rollback on error.
- **Native `analyzeHeadless` runner** with exact argv, no shell, no normalization &mdash; for batch headless workflows that don't need a live session.
- **Private mode-0700 workspace** per process; projects stay ephemeral, persistence is caller-owned `.gzf` snapshots.
- **Open-world escape hatches** &mdash; `ghidra.call`, `ghidra.eval`, and `ghidra.script` reach the live Ghidra Java/Python runtime when the typed surface isn't enough.
- **Fail-fast validation** &mdash; Ghidra installation is checked at startup before the MCP loop begins.

## Architecture

```
┌──────────────┐  stdio (MCP JSON-RPC)  ┌──────────────────────────┐
│  MCP client  │ ◄────────────────────► │   Ryuumonbuchi server    │
│  (LLM agent) │                        │   (low-level SDK, 216     │
└──────────────┘                        │    dynamic tools)         │
                                        └───────────┬──────────────┘
                                                    │ socket-framed IPC
                                                    ▼
                                        ┌──────────────────────────┐
                                        │  Persistent worker child  │
                                        │  (one PyGhidra/JVM        │
                                        │   session per lifespan)   │
                                        └───────────┬──────────────┘
                                                    │ Jep / PyGhidra
                                                    ▼
                                        ┌──────────────────────────┐
                                        │   Ghidra backend          │
                                        │   (program sessions,      │
                                        │    decompiler, analysis)  │
                                        └──────────────────────────┘
                                                    │
                          native runner ───────────►│ analyzeHeadless (subprocess)
```

**Three dispatch paths:**

1. **Worker tools** (212) &mdash; validated against the catalog schema, sent to the persistent child over an 8-byte length-prefixed frame protocol, executed against a live Ghidra program session.
2. **`headless.run`** &mdash; spawns `analyzeHeadless` directly with exact argv in a child process group; full FS/process/network access by default.
3. **`operation.batch`** &mdash; 1&ndash;32 worker tools executed atomically; read-only batches run without a transaction, mutating batches wrap in one undo transaction with rollback on error.

Every tool response carries a compact text summary plus the full structured payload (JSON). Large results spill to mode-0600 files under the private workspace and are referenced by path.

## Install

### Prerequisites

- **Python 3.13** (only supported runtime)
- **Ghidra** installed locally (default lookup path: `/usr/share/ghidra`; override with `--ghidra-install-dir` or `GHIDRA_INSTALL_DIR`). Ghidra bundles its own JDK; no separate Java install is needed if Ghidra is present.
- [**uv**](https://docs.astral.sh/uv/) (recommended) or any PEP 517 build frontend.

### From source

```bash
git clone <your-repo-url> ryuumonbuchi
cd ryuumonbuchi
uv sync                # installs runtime + dev deps, creates .venv
```

### Run

```bash
uv run ryuumonbuchi                           # stdio MCP server
uv run ryuumonbuchi --version                 # print version and exit
uv run ryuumonbuchi --ghidra-install-dir /opt/ghidra
```

The server reads MCP JSON-RPC from stdin and writes to stdout. Point your MCP client at the `ryuumonbuchi` executable.

> [!NOTE]
> Startup validates the Ghidra installation (layout, version, supported Python/Java) and exits with code 2 on failure before entering the MCP loop.

## Configuration

Precedence is **CLI flag &gt; environment variable &gt; built-in default**.

| CLI flag | Environment variable | Default | Description |
|---|---|---|---|
| `--ghidra-install-dir PATH` | `GHIDRA_INSTALL_DIR` | `/usr/share/ghidra` | Ghidra installation root |
| `--max-heap-mb MIB` | `RYUUMONBUCHI_MAX_HEAP_MB` | `1024` | Worker JVM max heap (256&ndash;8192) |
| `--max-cpu COUNT` | `RYUUMONBUCHI_MAX_CPU` | `2` | Worker CPU affinity core count (1&ndash;64) |
| `--operation-timeout-seconds SECONDS` | `RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS` | `900` | Per-operation wall-clock deadline |
| `--max-import-bytes BYTES` | `RYUUMONBUCHI_MAX_IMPORT_BYTES` | `67108864` | Cap on `program.open_bytes` payloads |
| `--max-response-bytes BYTES` | `RYUUMONBUCHI_MAX_RESPONSE_BYTES` | `4194304` | Inline response cap before spill-to-file |
| `--max-log-tail-bytes BYTES` | `RYUUMONBUCHI_MAX_LOG_TAIL_BYTES` | `65536` | Worker log tail returned on failure |
| `--classpath PATH` (repeatable) | `RYUUMONBUCHI_CLASSPATH` (path-sep) | &mdash; | Extra Java classpath entries |
| `--class-file PATH` (repeatable) | `RYUUMONBUCHI_CLASS_FILES` (path-sep) | &mdash; | Extra Java class files to load |
| `--vmarg ARG` (repeatable) | `RYUUMONBUCHI_VMARGS` (shlex) | &mdash; | Extra JVM arguments |

> [!IMPORTANT]
> Filesystem-writing tools (`program.export`, `program.export_packed`, `program.save_as`) are gated by `RYUUMONBUCHI_ALLOW_EXPORT`. Byte imports (`program.open_bytes`) are gated by `RYUUMONBUCHI_ALLOW_IMPORT_BYTES` and bounded by `RYUUMONBUCHI_MAX_IMPORT_BYTES`. Both default to disabled for safety.

## Tool surface

All 216 tools use dotted names and accept a JSON object. Most backend tools take a `session_id` (returned by `program.open` / `program.open_bytes`) and are batch-eligible. A representative slice:

| Category | Example tools |
|---|---|
| **Program & session** | `program.open`, `program.open_bytes`, `program.close`, `program.summary`, `program.report`, `program.mode.set`, `program.image_base.set`, `program.save`, `program.export_packed` |
| **Analysis** | `analysis.update`, `analysis.update_and_wait`, `analysis.status`, `analysis.options.list`/`get`/`set`, `analysis.analyzers.list`/`set`, `analysis.clear_cache` |
| **Listing & disassembly** | `listing.disassemble.function`, `listing.disassemble.range`, `listing.disassemble.seed`, `listing.code_units.list`, `listing.data.at`/`create`/`clear`, `listing.clear` |
| **Decompilation** | `decomp.function`, `decomp.tokens`, `decomp.ast`, `decomp.high_function.summary`, `decomp.writeback.params`/`locals`, `decomp.override.get`/`set`, `decomp.trace_type.forward`/`backward`, `decomp.global.rename`/`retype` |
| **P-code** | `pcode.function`, `pcode.block`, `pcode.op.at`, `pcode.varnode_uses` |
| **Functions** | `function.list`, `function.at`, `function.by_name`, `function.report`, `function.create`/`delete`, `function.rename`, `function.signature.get`/`set`, `function.callers`/`callees`/`variables`, `function.batch.run` |
| **Symbols & namespaces** | `symbol.list`/`by_name`/`create`/`delete`/`rename`/`primary.set`, `namespace.create`, `class.create`, `symbol.namespace.move` |
| **Memory** | `memory.blocks.list`, `memory.read`/`write`, `memory.block.create`/`remove` |
| **Types & layouts** | `type.list`/`get`/`define_c`/`parse_c`/`apply_at`/`rename`/`delete`, `layout.struct.*`, `layout.enum.*`, `layout.union.*`, `type.category.*`, `type.archives.list` |
| **References** | `reference.to`/`from`, `reference.create.memory`/`stack`/`register`/`external`, `reference.delete`, `reference.clear_from`/`to`, `reference.association.set`/`remove` |
| **Search** | `search.text`, `search.bytes`, `search.constants`, `search.instructions`, `search.pcode`, `search.defined_strings`, `search.resolve` |
| **Graph** | `graph.basic_blocks`, `graph.cfg.edges`, `graph.call_paths` |
| **Comments, bookmarks, tags** | `comment.get`/`get_all`/`set`/`list`, `bookmark.add`/`list`/`remove`/`clear`, `tag.add`/`list`/`remove`/`stats` |
| **Patching** | `patch.assemble`, `patch.nop`, `patch.branch_invert` |
| **Transactions & tasks** | `transaction.begin`/`commit`/`revert`/`undo`/`redo`/`status`, `task.analysis_update`/`status`/`result`/`cancel` |
| **Variables & params** | `variable.rename`/`retype`/`local.create`/`remove`/`comment.set`, `parameter.add`/`remove`/`move`/`replace`, `stackframe.variables`/`create`/`clear` |
| **External & source** | `external.imports.list`/`exports.list`/`library.*`/`location.*`/`function.create`/`entrypoint.*`, `source.file.*`, `source.map.*`, `relocation.list`/`add`, `equate.*` |
| **Projects** | `project.folders.list`, `project.files.list`, `project.file.info`/`delete`, `project.program.open`, `project.search.programs` |
| **Open world** | `ghidra.call`, `ghidra.eval`, `ghidra.script` (each transitions read-only sessions to writable with `write=true`) |
| **Server-native** | `health.ping`, `mcp.response_format`, `headless.run`, `operation.batch` |

## Usage

### Typical agent flow

```python
# 1. Open a binary -> get session_id
session = mcp.call("program.open", {"path": "/bin/ls"})

# 2. Run auto-analysis
mcp.call("analysis.update_and_wait", {"session_id": session["session_id"]})

# 3. List functions, then decompile one
funcs = mcp.call("function.list", {"session_id": session["session_id"], "limit": 20})
decomp = mcp.call("decomp.function", {
    "session_id": session["session_id"],
    "function_start": funcs["functions"][0]["address"],
})

# 4. Rename, retype, retag &mdash; batched in one transaction
mcp.call("operation.batch", {
    "session_id": session["session_id"],
    "operations": [
        {"tool": "function.rename", "arguments": {"session_id": sid, "function_start": addr, "name": "entry"}},
        {"tool": "comment.set",      "arguments": {"session_id": sid, "address": addr, "comment": "main entry"}},
    ],
})

# 5. Snapshot and close
mcp.call("program.export_packed", {"session_id": sid, "destination_path": "/tmp/ls.gzf"})
mcp.call("program.close", {"session_id": sid})
```

### Open-world scripting

When the typed surface doesn't cover a need, drop into the live runtime:

```python
# Evaluate Python inside the live Ghidra JVM context (PyGhidra/Jep)
mcp.call("ghidra.eval", {"code": "print(currentProgram.getName())", "write": False})

# Run an arbitrary Ghidra script against the open session
mcp.call("ghidra.script", {"path": "/scripts/MyScript.py", "session_id": sid, "write": True})
```

### Headless batch jobs

For workflows that don't need a live session, `headless.run` invokes `analyzeHeadless` directly:

```python
mcp.call("headless.run", {
    "arguments": [
        "/tmp/project", "TempProj",
        "-import", "/bin/ls",
        "-postScript", "AnalyzeAll.java",
        "-deleteProject",
    ],
    "timeout_seconds": 300,
})
```

## License

GPL-2.0-only &mdash; see [LICENSE](LICENSE).
