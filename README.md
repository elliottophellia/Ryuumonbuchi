# Ryuumonbuchi
maybe the headless ghidra mcp you are looking for

Ryuumonbuchi connects an MCP client to headless Ghidra over stdio. Use it to import a binary, inspect functions and memory, patch bytes, or save a snapshot.

Workers are disposable on purpose. Each request starts a JVM, reads the result, and tears the worker down. That keeps Ghidra state out of the parent and gives uncertain mutations a clean recovery path.

## Requirements

- Linux/POSIX host
- Python 3.13
- `uv` 0.11 or newer
- Ghidra 12.0 or newer with PyGhidra and the `support/analyzeHeadless` launcher
- Java 21 or newer

## Quick start

Try the released tag:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi@v0.2.0 ryuumonbuchi
```

Use the current source tree:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi ryuumonbuchi
```

From a checkout on your machine:

```bash
uvx --from . ryuumonbuchi
python -m ryuumonbuchi
```

If Ghidra is installed somewhere other than `/usr/share/ghidra`, set `GHIDRA_INSTALL_DIR` or pass `--ghidra-install-dir`. Ryuumonbuchi checks the host, Ghidra layout, metadata, Python support, and limits before opening MCP stdio. A bad setup prints the problem and exits with status 2, before a server can start in a broken state.

## MCP client configuration

Most MCP clients can use a setup like this. Change the Ghidra path if needed:

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

CLI wins. If a flag is absent, its environment variable wins. If that is absent too, the default applies. Boolean environment values are case-insensitive: `0`, `false`, `no`, and `off` mean false; `1`, `true`, `yes`, and `on` mean true.

| Environment variable | Default | Bounds / meaning |
| --- | --- | --- |
| `GHIDRA_INSTALL_DIR` | `/usr/share/ghidra` | Existing Linux Ghidra 12.0+ installation |
| `RYUUMONBUCHI_MAX_HEAP_MB` | `1024` | 256..8192 MiB |
| `RYUUMONBUCHI_MAX_CPU` | `2` | 1..host CPU count |
| `RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS` | `900` | 30..3600 seconds |
| `RYUUMONBUCHI_MAX_IMPORT_BYTES` | `67108864` | Positive decoded byte-import limit; 64 MiB default |
| `RYUUMONBUCHI_ALLOW_EXPORT` | `true` | Boolean; controls executable export and GZF save |
| `RYUUMONBUCHI_ALLOW_IMPORT_BYTES` | `true` | Boolean; controls base64 byte import |

Responses top out at 4 MiB, and failure logs keep a 64 KiB tail. These are fixed internal limits. `health` reports them; no environment variable changes them.

## MCP tools

Every program-bound call takes an explicit `program_name`. The server never guesses which imported program you meant.

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

The server stays narrow: no general filesystem browser, arbitrary script or Java execution, GUI transport, network transport, or unbounded project enumeration.

## Limits

The tool bounds are:

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

`program_import` reads the source path you provide. Its source-path field has no application-level length bound. If the bytes are already in hand, `program_import_bytes` accepts caller-owned base64 data and applies `RYUUMONBUCHI_MAX_IMPORT_BYTES` after decoding.

## Examples

Import a normal file:

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

Import bytes you already have:

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

Patch one instruction, then export the result:

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

The worker writes export and save destinations. Relative paths are resolved by the parent MCP process against its current working directory before the worker starts. Existing export destinations are refused unless `overwrite` is `true`, so the original file stays untouched when a request is refused.

Save a lossless GZF snapshot:

```json
{
  "name": "program_save",
  "arguments": {
    "program_name": "hello",
    "destination_path": "./hello.gzf"
  }
}
```

That snapshot stays at the destination you chose. Import it later with `program_import` to restore the saved analysis, types, symbols, comments, and patches. Ryuumonbuchi does not search for snapshots or copy them into a permanent project.

## Session and security semantics

Sessions are disposable. Each one gets a random private workspace with mode `0700`, an owner lock, and an ephemeral Ghidra project. Each request gets one JVM worker, a private request directory, and a filtered environment.

If a mutating worker fails and its result is uncertain, the server replaces the session before queued state-changing work or an explicit `session_clear` can use the old one. The error includes the replacement session ID. The old workspace is not copied into the new one.

Import paths are read; export and save paths are written. Workers provide process and resource boundaries, but they are not an OS sandbox. The server does not expose arbitrary scripts, GUI controls, network transport, a general filesystem browser, or arbitrary Java execution.

## Contributor verification

Run these before opening a PR:

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

The real-Ghidra tests need a provisioned host:

```bash
PYTHONWARNINGS=error uv run pytest -m live -W error -q
```

Ryuumonbuchi is GPL-2.0-only. Delivery is Git-only; there is no PyPI publication workflow.