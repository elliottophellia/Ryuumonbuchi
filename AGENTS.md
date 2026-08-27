# AGENTS.md

Instructions for contributors who edit this repository. These are durable conventions, not a checklist for a single task.

## Scope and source map

`src/ryuumonbuchi/` holds the package. `tests/` holds the contracts.

| Path | Role |
|---|---|
| `src/ryuumonbuchi/__init__.py` | Package version (`__version__`) |
| `src/ryuumonbuchi/__main__.py` | Module entry bridge to the CLI |
| `src/ryuumonbuchi/py.typed` | PEP 561 type marker |
| `src/ryuumonbuchi/cli.py` | Startup, argument parsing, exit code 2 on config failure |
| `src/ryuumonbuchi/config.py` | Limits, validation, environment names, precedence |
| `src/ryuumonbuchi/server.py` | MCP boundary and policy dispatch |
| `src/ryuumonbuchi/catalog/__init__.py` | Authoritative tool schemas and annotations |
| `src/ryuumonbuchi/catalog/schema.py` | `ToolSpec` dataclass and input-schema helpers |
| `src/ryuumonbuchi/catalog/order.py` | Canonical tool ordering |
| `src/ryuumonbuchi/catalog/program.py` | Program/project/transaction/metadata specs |
| `src/ryuumonbuchi/catalog/analysis.py` | Analysis/decompiler/graph/task specs |
| `src/ryuumonbuchi/catalog/listing.py` | Memory/listing/context/patch specs |
| `src/ryuumonbuchi/catalog/search.py` | Search specs |
| `src/ryuumonbuchi/catalog/symbols.py` | Symbol/comment/bookmark/namespace/tag specs |
| `src/ryuumonbuchi/catalog/references.py` | External/reference/equate/source/relocation specs |
| `src/ryuumonbuchi/catalog/functions.py` | Function/parameter/variable/stackframe specs |
| `src/ryuumonbuchi/catalog/types.py` | Type/layout specs |
| `src/ryuumonbuchi/catalog/special.py` | Special-routed specs (`health.ping`, `headless.run`, etc.) |
| `src/ryuumonbuchi/process.py` | Parent worker lifecycle |
| `src/ryuumonbuchi/models.py` | Protocol-v2 wire frames |
| `src/ryuumonbuchi/worker/__main__.py` | Child dispatch and result spilling |
| `src/ryuumonbuchi/backend/__init__.py` | `GhidraBackend` façade: re-exports and mixin composition only |
| `src/ryuumonbuchi/backend/state.py` | State: config, error type, session/task records |
| `src/ryuumonbuchi/backend/core.py` | `_BackendCore`: startup, ping, shutdown, shared helpers |
| `src/ryuumonbuchi/backend/records.py` | `_RecordMixin`: record/dict conversion helpers |
| `src/ryuumonbuchi/backend/resolvers.py` | `_ResolverMixin`: symbol/type/category resolution helpers |
| `src/ryuumonbuchi/backend/program.py` | `_ProgramMixin`: session/project/lifecycle/export operations |
| `src/ryuumonbuchi/backend/analysis.py` | `_AnalysisMixin`: analysis, decompiler, graph, task operations |
| `src/ryuumonbuchi/backend/listing.py` | `_ListingMixin`: memory, disassembly, patch, listing operations |
| `src/ryuumonbuchi/backend/search.py` | `_SearchMixin`: string/byte/constant/instruction search |
| `src/ryuumonbuchi/backend/symbols.py` | `_SymbolMixin`: symbols, annotations, bookmarks, namespaces, tags |
| `src/ryuumonbuchi/backend/references.py` | `_ReferenceMixin`: imports/exports, xrefs, external metadata, equates |
| `src/ryuumonbuchi/backend/functions.py` | `_FunctionMixin`: function/parameter/variable operations |
| `src/ryuumonbuchi/backend/types.py` | `_TypeMixin`: type/struct/enum/layout operations |
| `src/ryuumonbuchi/native.py` | Exact `analyzeHeadless` execution |
| `src/ryuumonbuchi/session.py` | Private workspace management |
| `tests/` | Catalog counts, schema invariants, CLI/config, lifecycle, live workflow |

## Invariants

Preserve these when editing. An intentional break requires updating the exact-set tests in the same change.

- Runtime is Python 3.11–3.13, Linux, Ghidra 12+.
- `health.ping` remains JVM-lazy; it never starts the backend.
- The catalog declares 216 unique dotted tool names and 212 one-to-one backend methods. Changing either count updates `tests/test_catalog.py`.
- Root schemas reject extra properties and bound arrays, pages, and payloads.
- Tool annotations (`read_only`, `destructive`, `open_world`, `batch_allowed`) must match the backend method's mutation behavior.
- Protocol changes update the parent, the worker, `models.py`, and lifecycle tests together.
- Worker and native processes stay shell-free and own their process groups.
- Workspaces and captures keep 0700 and 0600 permissions.
- Import and export stay default-deny behind `RYUUMONBUCHI_ALLOW_EXPORT` and `RYUUMONBUCHI_ALLOW_IMPORT_BYTES`.

## Change recipes

Match the changed surface to the affected tests.

- Tool change: update the backend method, the `ToolSpec`, the exact catalog expectations, and the dispatch/live tests.
- IPC change: update `SCHEMA_VERSION`, framing, both endpoints, and lifecycle/model tests.
- Config change: update CLI, environment, default, and validation tests, and the README table.
- Native change: prove exact argv, environment, captures, timeout, and reaping.
- Mutation change: prove read-only rejection, transaction rollback, undo/redo, and readback.

## Commands

Setup and targeted testing first:

```bash
uv sync --locked --all-groups
uv run pytest tests/test_mcp_client_smoke.py tests/test_worker_lifecycle.py -q
```

Quality gates:

```bash
uv run pytest -m "not live and not live_server" --cov=ryuumonbuchi --cov-branch --cov-report=term-missing --cov-fail-under=100
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright
uv build --no-sources
```

The live matrix needs `GHIDRA_INSTALL_DIR`, Java 21+, and `cc`:

```bash
RYUUMONBUCHI_REQUIRE_LIVE=1 GHIDRA_INSTALL_DIR=/usr/share/ghidra uv run pytest -m live tests/test_live_workflow.py -q
```

The `live_server` marker is separate. It requires `RYUUMONBUCHI_TEST_GHIDRA_URL` plus a valid Ghidra install; the current collected suite has no tests using it. Missing live prerequisites skip unless `RYUUMONBUCHI_REQUIRE_LIVE=1` turns the skip into a failure.

## Conventions

- 100-column Ruff formatting.
- Strict types, except the existing targeted suppressions.
- Conventional Commit subjects.
- No legacy underscore MCP tool names.
- No hand-edited generated caches or build artifacts.
- Comments and docstrings describe current behavior, not the diff that produced it.