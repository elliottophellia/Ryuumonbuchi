# Ryuumonbuchi 0.2.0 Plan

Driven by the "Flag Printer 2100" CTF test, which exercised a complete RE
workflow: import → strings → decompile → disassemble → patch → (gap: export) →
(gap: run patched binary).

## Defects (test-found)

### D1. `function_decompile` / `function_get` / `call_graph` selector schema

`address` and `name` are shown as independent `Optional` fields in the
generated JSON Schema, but the `SelectorOperation` model validator rejects
when neither or both are set. Clients cannot see the exclusivity constraint
and fail with validation errors.

Fix: encode the exactly-one constraint in the tool schema (e.g. `oneOf`
in the generated schema), so clients see the contract before calling.

### D2. `search_strings` noise

Returns every overlapping substring at every offset (20 hits for one
20-character string). Fix:

- Deduplicate overlapping matches: keep the longest match per start position.
- Add a `min_length` parameter (default 4).

### D3. `program_export` missing

The test required patching the binary and running the patched result.
`edit_patch_bytes` works in the Ghidra program, but there is no way to
persist the patched bytes. Add `program_export`:

- Writes program bytes to a caller-supplied path.
- Bounded by the existing response/size limits policy.
- Atomic write (temp file + rename).
- Gated by `RYUUMONBUCHI_ALLOW_EXPORT` env (default `1`, set `0` to disable).

## Features

### F1. `program_import_bytes`

Import from base64-encoded bytes. Removes the shared-filesystem requirement
for remote MCP clients. Bounded by a configurable size limit
(default 64 MiB).

### F2. `analysis_list_analyzers`

List available Ghidra analyzers (id, name, enabled status). Complements the
existing `analysis_options_get` / `analysis_options_set` by making the
analyzer registry discoverable.

### F3. `edit_set_data_type`

Apply a data type (string, dword, qword, pointer, ...) at an address.
Standard RE operation.

### F4. `search_strings` `defined_only` flag

When `true`, use Ghidra's defined string data (fast, no noise, respects
auto-analysis). When absent or `false`, keep the raw scan with the D2
dedupe and `min_length` improvements.

### F5. `health` limits

Return `max_heap_mb`, `max_cpu`, `operation_timeout_seconds`, and
`max_response_bytes` in the health response so clients can adapt batch
sizes and timeouts.

### F6. `program_info` architecture

Add `processor` and `language_id` fields to `ProgramInfo`.

## Opt-in persistence

### P1. `RYUUMONBUCHI_PERSISTENT_PROJECT` env

When set, the session workspace is not deleted on MCP shutdown. Programs
survive across restarts. Adds a `program_save` operation. Default remains
ephemeral. Persistent projects are filesystem state outside the MCP process;
gated explicitly and documented as an ownership boundary, not a sandbox.

## Rejected / deferred

- **Dynamic execution / emulation**: out of scope for 0.2.0. Ghidra
  Debugger/Emulator integration is heavyweight and changes the security
  model. Non-goal, documented.
- **Warm worker pool**: one-shot worker isolation is deliberate. Deferred to
  0.3+ as an opt-in configuration flag.
- **GUI controls, arbitrary scripts, network transport**: never.

## Release engineering

- Version bump `0.1.0` → `0.2.0` in `pyproject.toml`.
- Add `CHANGELOG.md` documenting all changes since 0.1.0.
- Live integration test: `test_print_flag_workflow` — import → decompile →
  disassemble → patch → export → run patched binary → assert flag
  `Alpaca{G00d_Morning_AlpacaH4ck!}`. Uses the existing `tests/print_flag`
  fixture.
- Git tag `v0.2.0`; update README invocation from `@v0.1.0` to `@v0.2.0`.

## Priority order

1. D1 schema fix
2. D2 strings noise
3. D3 program export
4. F1 import bytes
5. F5 health limits + F6 program info architecture
6. F2 analyzers + F3 data type
7. F4 defined strings
8. P1 persistence (needs design discussion)
9. Release engineering (last)
