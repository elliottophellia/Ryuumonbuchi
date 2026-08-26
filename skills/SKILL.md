---
name: ryuumonbuchi
description: Operate the Ryuumonbuchi MCP server for headless Ghidra reverse engineering. Use when driving decompilation, disassembly, patching, type and symbol recovery, memory edits, transactions, and Ghidra project analysis through a Ryuumonbuchi stdio server. Covers the safe read-only-first workflow, session and address discipline, mutation and transaction rules, headless.run, task and error recovery, raw ghidra.call/ghidra.eval/ghidra.script escape hatches, and a sleep/timing-gate bypass recipe.
license: GPL-2.0-only
compatibility: Linux, Python 3.13, Ghidra 12.0 or newer with Java 21+
metadata:
  version: "0.5.0"
---

# Ryuumonbuchi

Ryuumonbuchi exposes a Ghidra reverse-engineering surface as an MCP server with 216 dotted tool names over 212 backend methods. One persistent worker child holds a lazy PyGhidra/JVM backend. Sessions open read-only by default.

## Safe workflow

1. `health.ping` to confirm the server answers; it never starts the JVM.
2. `program.open` with `path` and `read_only: true`. Leave `update_analysis: true` for the normal one-call path, or set it false when analysis options must change first.
3. Run analysis: `analysis.update_and_wait` (synchronous) or `analysis.update` then poll `task.status` and fetch `task.result`.
4. Typed discovery: `program.summary`, `function.list`, `search.*`, `symbol.*`.
5. Transition to writable only with mutation intent: `program.mode.set`.
6. Mutate, then verify by readback.
7. Authorized export.
8. `program.close`.

Analysis updates the Ghidra database and is cataloged as mutating, so it is allowed on a session whose edit mode is read-only. Run analysis outside `operation.batch`.

## Tool choice

Prefer `program.summary` and `program.report` first, then `search.*` and `function.*`, then `decomp.function` plus listing, p-code, references, and graph tools. Move to types/layouts and typed mutation tools when the recovered surface is clear. Reserve `ghidra.call`, `ghidra.eval`, and `ghidra.script` for gaps in the typed catalog.

For declaration-heavy functions, `decomp.function` with `view: "compact"` is useful for initial reading. Compact output is declaration-elided and non-compilable; return to the default raw view, `decomp.tokens`, `decomp.ast`, or p-code for exact analysis.

Raw tools reject a read-only session unless `write: true` is set. `write: true` permanently transitions the selected session (or every open session, for sessionless writable eval) to writable.

## Address discipline

Tools accept integer or string addresses. Prefer decimal integers when feeding tool output back through an agent adapter, because some normalizers misread hex-looking strings. Resolve uncertain symbols with `search.resolve`, `symbol.by_name`, or `function.by_name`. Never guess an address.

Function resolution remains strict: tools accept exact entries or addresses contained within a function, but never select a nearby function for an unresolved address. The error reports the normalized address and nearest previous and next function entries with distances; use those hints to correct the input.

Concretely, hex strings containing the digit `e` (e.g. `"001019e7"`) get stripped of leading zeros and parsed as scientific notation (`1019e7`) by some adapters, routing every address-taking tool to a bogus `ram:` address. Compute the integer once and pass it everywhere: `printf '%d' 0x1019e7` → `1055207`. `function.list` and `search.defined_strings` return addresses as hex strings; convert to `int` before feeding back into `memory.read`, `memory.write`, `patch.*`, `decomp.function`, or `listing.*`.

## Mutation discipline

Check `program.mode.get`, and change to `read_only: false` only with mutation intent. Use one mutating call for its automatic transaction, `operation.batch` for 1 to 32 atomic calls with rollback, or explicit `transaction.begin`/`commit`/`revert` for a multi-step sequence. Verify through disassembly, memory, symbol, type, or decompilation readback before export.

For x86 NOP work, prefer `patch.nop`, verify `bytes_nopped` plus memory or listing, and fall back to the manual sequence only after the typed tool fails: (1) `program.mode.set` → `read_only: false`; (2) `listing.disassemble.function` on the target and sum the byte lengths of the instructions to NOP; (3) `listing.clear` `{start, length, clear_comments: true}` — raw `memory.write` over a defined instruction raises `MemoryAccessException: Memory change conflicts with instruction`; (4) `memory.write` `{address, data_hex: "90" * N}`; (5) verify with `memory.read` plus `listing.disassemble.function`. The SLEIGH assembler rejects the `NOP` mnemonic on x86, and a failed `patch.assemble` can half-write memory inside a transaction that does not roll back — never attempt the assembler first for NOPs.

## Task and error recovery

Do not start overlapping analysis on one session. Poll `task.status` until `completed`, `failed`, or `cancelled` before `task.result`. Call `task.cancel` on request. Error codes include `invalid_params`, `ghidra_error`, `worker_timeout`, `worker_cancelled`, `worker_failed`, and `native_spawn_failed`. After a worker timeout, cancel, or crash, call `health.ping`, compare `backend_generation`, and reopen the binary; old session IDs are gone.

## Output and cleanup

The first `TextContent` is a compact summary; the second is the full JSON. Use `mcp.response_format` when adapting a client. Native output may be truncated inline; full capture paths come back on the result. Export and byte-import gates must be enabled at server startup, exports reject unsafe or symlink targets, and packed exports default to no overwrite. Close sessions, and treat the private workspace as ephemeral.

## Development

The server runs `uvx --from <repo> ryuumonbuchi` and caches parent-side modules (`process.py`, `backend.py`) in `sys.modules`, so editing source does not take effect in a running server. Restart the server **python** PID (not the `uvx` wrapper) and confirm via `health.ping` — a fresh `backend_generation` UUID means the new code is live. The worker child re-imports `ryuumonbuchi.worker` from disk on each spawn, so worker-side edits load on the next tool call without a server restart. Clear `.pyc`/`__pycache__` under the installed `site-packages/ryuumonbuchi` after syncing source → installed to avoid stale bytecode.

## Worked recipe: sleep/timing-gate bypass

When a CTF binary gates flag output behind a long `sleep()` before printing, patch the call out and let the binary compute the flag itself — faster and more reliable than reimplementing its obfuscation.

1. `health.ping`, then `program.open` `{path}` → capture `session_id` (opens read-only).
2. Survey: `function.list` + `search.defined_strings` to find `main`, the flag function, and any plaintext.
3. `decomp.function` `{session_id, function_start}` on `main` and the flag function; identify the `sleep(<arg>)` call.
4. `listing.disassemble.function` `{session_id, address}` to get the exact bytes/offsets of the `MOV EDI,<arg>` and `CALL sleep` instructions (a large arg like `0x8d12cea0` ≈ 75 years confirms the gate).
5. `program.mode.set` `{session_id, read_only: false}`.
6. `patch.nop` `{session_id, address, count}` over the argument-load and the call.
7. Re-`listing.disassemble.function` to confirm the instructions collapsed.
8. `program.export_binary` `{session_id, path, format: "original_file"}` — byte-faithful ELF (output size matches input for code-only patches).
9. `chmod +x` and run; the flag prints instantly.

## Examples

Read-only analysis:

```json
{"tool": "program.open", "arguments": {"path": "/samples/binary", "read_only": true}}
{"tool": "analysis.update_and_wait", "arguments": {"session_id": "<session_id>"}}
```

Atomic rename and comment batch (requires a writable session):

```json
{"tool": "operation.batch", "arguments": {
  "session_id": "<session_id>",
  "operations": [
    {"tool": "symbol.rename", "arguments": {"address": 4198400, "new_name": "entry"}},
    {"tool": "comment.set", "arguments": {"address": 4198400, "comment": "entry point"}}
  ]
}}
```

Tracked analysis task:

```json
{"tool": "analysis.update", "arguments": {"session_id": "<session_id>"}}
{"tool": "task.status", "arguments": {"task_id": "<task_id>"}}
```

Writable transition and verified NOP patch:

```json
{"tool": "program.mode.set", "arguments": {"session_id": "<session_id>", "read_only": false}}
{"tool": "patch.nop", "arguments": {"session_id": "<session_id>", "address": 4198400, "count": 1}}
```

Raw tool call (transitions the session to writable):

```json
{"tool": "ghidra.eval", "arguments": {"session_id": "<session_id>", "code": "currentProgram.getName()", "write": true}}
```