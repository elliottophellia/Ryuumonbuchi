# Ryuumonbuchi
maybe the headless ghidra mcp you are looking for

Ryuumonbuchi is a stdio MCP server for headless Ghidra analysis. An MCP client starts one server process, communicates through standard input and output, and calls a finite catalog of typed tools.

The MCP process does not embed a JVM. Each request launches one short-lived Ghidra worker, with a filtered environment and a private request directory. Workers open the selected program, perform the requested operation, return structured JSON, and exit.

## Requirements

- Linux/POSIX host
- Python 3.13
- `uv` 0.11 or newer
- Ghidra 12.0 or newer with PyGhidra and the `support/analyzeHeadless` launcher
- Java 21 or newer

## Quick start

Run the tagged release directly from Git:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi@v0.2.0 ryuumonbuchi
```

For the moving source tree:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi ryuumonbuchi
```

From a local checkout:

```bash
uvx --from . ryuumonbuchi
python -m ryuumonbuchi
```

Set `GHIDRA_INSTALL_DIR` or pass `--ghidra-install-dir` when Ghidra is not at `/usr/share/ghidra`. Startup validates Linux, the Ghidra layout and metadata, Python compatibility, and the configured limits before opening MCP stdio. Invalid configuration fails fast with a diagnostic and exit status 2; no partially started server remains.

## MCP client configuration

A complete stdio client configuration using the supported environment variable:

```json
{
  "mcpServers": {
    "ryuumonbuchi": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/elliottophellia/Ryuumonbuchi@v0.2.0",
        "ryuumonbuchi"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/usr/share/ghidra"
      }
    }
  }
}
```

## CLI

| Flag | Meaning |
| --- | --- |
| `--ghidra-install-dir PATH` | Ghidra installation directory |
| `--max-heap-mb MIB` | Worker JVM heap; 256..8192 MiB |
| `--max-cpu COUNT` | Worker CPU limit; 1..host CPU count |
| `--operation-timeout-seconds SECONDS` | Operation timeout; 30..3600 seconds |
| `--version` | Print `0.2.0` and exit |

## Configuration

Precedence is CLI option, then environment variable, then default. The boolean environment values `0`, `false`, `no`, and `off` disable a setting; `1`, `true`, `yes`, and `on` enable it, case-insensitively and with surrounding whitespace ignored.

| Environment variable | Default | Bounds / meaning |
| --- | --- | --- |
| `GHIDRA_INSTALL_DIR` | `/usr/share/ghidra` | Existing Linux Ghidra 12.0+ installation |
| `RYUUMONBUCHI_MAX_HEAP_MB` | `1024` | 256..8192 MiB |
| `RYUUMONBUCHI_MAX_CPU` | `2` | 1..host CPU count |
| `RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS` | `900` | 30..3600 seconds |
| `RYUUMONBUCHI_MAX_IMPORT_BYTES` | `67108864` | Positive decoded byte-import limit; 64 MiB default |
| `RYUUMONBUCHI_ALLOW_EXPORT` | `true` | Boolean; controls executable export and GZF save |
| `RYUUMONBUCHI_ALLOW_IMPORT_BYTES` | `true` | Boolean; controls base64 byte import |

The 4 MiB response limit and 64 KiB failure-log tail are fixed internal limits. `health` reports both values; neither is an environment variable.

## MCP tools

### Session and health

`health`, `session_status`, `session_clear`

### Program lifecycle

`program_import`, `program_import_bytes`, `program_delete`, `program_list`, `program_info`, `program_export`, `program_save`

### Inspection

`function_list`, `function_get`, `function_decompile`, `listing_disassemble`, `listing_data`, `memory_blocks`, `memory_read`, `search_strings`, `search_symbols`, `list_imports`, `list_exports`, `references`, `call_graph`, `byte_search`, `text_search`

### Analysis

`analysis_run`, `analysis_options_get`, `analysis_options_set`, `analysis_list_analyzers`

### Editing

`edit_rename_function`, `edit_rename_variable`, `edit_set_comment`, `edit_set_data_type`, `edit_set_prototype`, `edit_patch_bytes`, `edit_undo`, `edit_redo`

### Batch

`batch`

Every program-bound tool requires an explicit imported `program_name`. There is no general filesystem browser, arbitrary script or Java execution, GUI transport, network transport, or unbounded project enumeration.

## Limits

| Contract | Limit |
| --- | --- |
| Page size | 1..500 |
| Memory read | Up to 65,536 bytes |
| Function decompile | Timeout 1..600 seconds; UTF-8 result cap 1 MiB |
| Auto-analysis | Timeout 1..3600 seconds |
| Call graph | Depth 1..5; nodes 1..500 |
| Batch | 1..32 operations |
| Undo / redo | 1..100 changes |
| Raw strings | Length 1..4096; default minimum 4 |
| Byte patterns | Up to 256 whitespace-separated tokens |
| Text scans | Up to 64 MiB |
| Program names | 1..128 characters |
| Export / save destinations | 1..4096 characters |

`program_import` reads the caller-selected source path. Its source-path field has no application-level length bound. `program_import_bytes` accepts caller-owned base64 data and is bounded by `RYUUMONBUCHI_MAX_IMPORT_BYTES`.

## Examples

Import a source path, then inspect it:

```json
{
  "name": "program_import",
  "arguments": {
    "source_path": "/home/user/bin/hello",
    "program_name": "hello",
    "analyze": true
  }
}
```

Import caller-owned base64 bytes instead of a source path:

```json
{
  "name": "program_import_bytes",
  "arguments": {
    "program_name": "hello",
    "data": "f0VMRg...",
    "analyze": true
  }
}
```

Patch bytes and export the resulting executable. Export and save destinations are written by the worker; relative destinations are canonicalized by the parent MCP process against its current working directory before launch.

```json
{
  "name": "edit_patch_bytes",
  "arguments": {
    "program_name": "hello",
    "address": "00101000",
    "bytes_hex": "90"
  }
}
```

```json
{
  "name": "program_export",
  "arguments": {
    "program_name": "hello",
    "destination_path": "./patched-hello",
    "overwrite": false
  }
}
```

Existing export destinations are refused unless `overwrite` is `true`; refusal leaves the existing file untouched. `program_save` writes a lossless GZF snapshot containing analysis, types, symbols, comments, and patches:

```json
{
  "name": "program_save",
  "arguments": {
    "program_name": "hello",
    "destination_path": "./hello.gzf"
  }
}
```

The snapshot is caller-owned. Re-import it explicitly in a later session with `program_import`; Ryuumonbuchi does not browse or persist it automatically.

## Session and security semantics

Each MCP lifespan gets a cryptographically random private workspace with mode `0700`, an owner lock, an ephemeral Ghidra project, and one JVM worker per request. A worker request runs with a filtered environment and a private request directory. If a mutating worker result is uncertain, the server installs a replacement session before queued state-changing work or an explicit `session_clear` can capture state; only the replacement ID is reported.

Explicit import paths are read. Explicit export and save paths are written. The worker process is isolated for ownership and resource control, but process isolation is not an OS sandbox. The catalog intentionally excludes arbitrary scripts, GUI controls, network transport, a general filesystem browser, and arbitrary Java execution.

## Contributor verification

Run the same local commands used by CI:

```bash
uv sync --locked --all-groups
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright
PYTHONWARNINGS=error uv run pytest -m "not live" -W error --cov=ryuumonbuchi --cov-branch --cov-report=term-missing --cov-fail-under=100
uv run python -c 'import shutil; from pathlib import Path; shutil.rmtree("dist", ignore_errors=True); Path("dist").mkdir()'
uv build --no-sources
uv run python -m ryuumonbuchi --version
bash -c 'shopt -s nullglob; wheels=(dist/ryuumonbuchi-*.whl); (( ${#wheels[@]} == 1 )); uvx --from "${wheels[0]}" ryuumonbuchi --version'
git diff --check
```

Real Ghidra verification is separate and requires a provisioned host:

```bash
PYTHONWARNINGS=error uv run pytest -m live -W error -q
```

The project is GPL-2.0-only. Delivery is Git-only; there is no PyPI publication workflow.