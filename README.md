# Ryuumonbuchi

Ryuumonbuchi is a GPL-2.0-only MCP server for headless Ghidra analysis. The MCP process never embeds a JVM: each Ghidra operation runs in a short-lived worker process.

## Requirements

- Linux/POSIX host
- Python 3.13
- `uv` 0.11 or newer
- Ghidra 12.0 or newer with the bundled PyGhidra feature and Java 21+
- A readable Ghidra installation, defaulting to `/usr/share/ghidra`

## Invocation

The canonical Git-backed invocation is:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi@v0.2.0 ryuumonbuchi
```

For the moving branch, omit `@v0.1.0`:

```bash
uvx --from git+https://github.com/elliottophellia/Ryuumonbuchi ryuumonbuchi
```

From a local checkout:

```bash
uvx --from . ryuumonbuchi
```

Set `GHIDRA_INSTALL_DIR` or pass `--ghidra-install-dir` when Ghidra is not at the default path. Startup validates the installation before MCP stdio begins.

## MCP client configuration

Configure the client to launch `ryuumonbuchi` with stdio. Example:

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

## Tool groups

- Session and health: `health`, `session_status`, `session_clear`
- Programs: import, byte import, delete, list, information, export, and GZF snapshots
- Inspection: functions, listing, memory, symbols, strings, references, graphs, and searches
- Analysis: auto-analysis, analyzer discovery, and analysis options
- Editing: names, comments, data types, prototypes, byte patches, undo, and redo
- Batch: bounded ordered reads and transactional mutations

Every program-bound call selects an explicit imported `program_name`. The catalog does not expose arbitrary scripts, Java calls, GUI controls, filesystem reads outside the selected binary, network transport, or unbounded project enumeration.

Filesystem-writing tools (`program_export` and `program_save`) are controlled by `RYUUMONBUCHI_ALLOW_EXPORT` (default enabled). `program_save` writes a lossless Ghidra `.gzf` snapshot; re-import it with `program_import` in a later ephemeral session.

## Limits and session semantics

Defaults are 1024 MiB heap, two CPU cores, 15-minute operation timeout, 4 MiB response size, a 64 KiB failure-log tail, and a 64 MiB base64 byte-import limit. Requests have bounded pages, reads, patches, patterns, graphs, decompilation, scans, and batches.

Each MCP process receives a cryptographically random private temporary session project. It is removed on normal shutdown, cancellation, EOF, or `session_clear`; `session_clear` returns both session IDs and never copies programs. A worker JVM exists only for one request and is closed before its response is accepted. Process isolation is an ownership and resource boundary, not an OS sandbox.

## Development

```bash
uv sync --locked --all-groups
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright
uv run pytest -m "not live" --cov=ryuumonbuchi --cov-branch --cov-report=term-missing --cov-fail-under=100
uv build --no-sources
```

The live suite uses the installed Ghidra and is run separately with `uv run pytest -m live -q`. Ghidra is an external dependency and is never bundled. Delivery is Git-only; no PyPI publishing workflow is provided.
