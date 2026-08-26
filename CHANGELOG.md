# Changelog

## 0.5.0 - 2026-08-26

### Added

- An opt-in compact `decomp.function` view for declaration-heavy functions. The default raw view remains complete Ghidra C; compact output is explicitly marked incomplete and non-compilable.

### Changed

- Split the PyGhidra backend into responsibility-focused mixins behind the unchanged `ryuumonbuchi.backend.GhidraBackend` façade, preserving the 216-tool catalog and 212 backend method contracts.
- Split the authoritative tool catalog into responsibility-focused spec modules behind the unchanged `ryuumonbuchi.catalog` façade, preserving all 216 tool definitions, 212 backend mappings, schemas, annotations, batch eligibility, and registry order.

### Fixed

- Unresolved function addresses now remain strict errors while reporting the normalized address and nearest previous and next function entries with distances.

## 0.4.0 - 2026-08-26

### Added

- `AGENTS.md` contributor instructions and `skills/SKILL.md` agent operating guide.
- Consolidated the `ryuumonbuchi-sleep-bypass` and `ryuumonbuchi-operational-gotchas` managed skills into `skills/SKILL.md`: added a Development section (server restart and parent/worker reload discipline), an expanded address-mangling note, the manual NOP fallback, and a worked sleep/timing-gate bypass recipe. Fixed the skill frontmatter `name` from `skills` to `ryuumonbuchi`.

### Changed

- Rewrote `README.md` from the source, tests, packaging metadata, and release history.
- Reconstructed the `0.3.0`, `0.2.0`, and `0.1.0` release history below.
- Restored the `ruff check`, `ruff format --check`, and `pyright` quality gates; fixed lint, formatting, and type diagnostics across `src/` and `tests/` with two narrow per-file exceptions for untyped Java interop (`backend.py`) and the catalog consistency assertions (`catalog.py`).

## 0.3.0 - 2026-08-25

### Added

- 216 dotted tool names backed by 212 one-to-one backend methods.
- Persistent protocol-v2 worker child with 8-byte length-prefixed socket IPC.
- Native `analyzeHeadless` runner with exact argv and its own process group.
- Multi-program/project session surface.
- Raw Ghidra bridges: `ghidra.call`, `ghidra.eval`, `ghidra.script`.
- Transaction, task, and batch support, including atomic `operation.batch`.
- Strict schemas that reject extra properties and bound arrays, pages, and payloads.

### Changed

- Switched from one-shot workers to one persistent child per MCP lifespan.
- Linux, Python 3.13, and Ghidra 12+ with Java 21+ are now validated at startup.
- Import and export are default-deny behind `RYUUMONBUCHI_ALLOW_EXPORT` and `RYUUMONBUCHI_ALLOW_IMPORT_BYTES`.

### Fixed

- Inherited worker FD and framing cleanup on failure paths.
- `patch.nop` on x86.
- Atomic no-clobber and symlink-safe exports.
- Native process-group timeout handling.
- Batch and mutation validation, plus spill-envelope handling.

## 0.2.0 - 2026-08-24

### Added

- `program_export` for patched executable images, with atomic writes and overwrite protection.
- `program_import_bytes` for bounded base64 imports without a shared filesystem.
- `program_save` for lossless Ghidra `.gzf` snapshots that can be re-imported later.
- Analyzer discovery through `analysis_list_analyzers`.
- Data definitions through `edit_set_data_type`.
- Defined-string mode for `search_strings`.
- `health` resource limits and imported program architecture metadata.
- `min_length` and maximal-run deduplication for raw string searches.
- Selector XOR constraints in tool JSON Schemas.
- Live Ghidra regression coverage for the Flag Printer 2100 workflow and GZF round trips.

### Changed

- Session projects remain ephemeral; persistence is represented by explicit caller-owned `.gzf` snapshots rather than durable Ghidra projects.
- Filesystem-writing tools are controlled by `RYUUMONBUCHI_ALLOW_EXPORT`.
- Byte imports are controlled by `RYUUMONBUCHI_ALLOW_IMPORT_BYTES` and bounded by `RYUUMONBUCHI_MAX_IMPORT_BYTES` (64 MiB default).

## 0.1.0 - 2026-08-24

### Added

- Validated ephemeral session workspaces.
- One-shot isolated workers.
- Typed analysis and editing tools.
- Stdio CLI.
- Bounded schemas.
- First non-live and live test split.