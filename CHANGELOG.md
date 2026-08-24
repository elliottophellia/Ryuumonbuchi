# Changelog

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

### Deferred

- Dynamic execution/emulation, warm worker pools, GUI controls, arbitrary scripts, and network transport remain out of scope.
