# Changelog

## [Unreleased]

## [0.2.0] — TBD

### Added
- Module `shadow-tool` (MCP03) — static analysis that flags tool names shadowing common
  built-ins (`bash`, `execute`, `read_file`, etc.) or matching dangerous-operation patterns
- Module `rug-pull` (MCP06) — re-enumerates the server surface after dynamic testing and diffs
  against the initial snapshot; detects tools added, removed, or mutated mid-session
- `HttpTransport` — full HTTP JSON-RPC transport (`--transport http --url <endpoint>`);
  replaces the previous `NotImplementedError` stub
- `OWASPCategory.MCP03_SHADOW_TOOL` enum value
- Mutating mock server (`tests/mock_mutating_server.py`) for MCP06 integration tests

### Fixed
- `pyproject.toml` build backend: `setuptools.backends.legacy` → `setuptools.build_meta`
- `info_disclosure`: credential regex now handles JSON-encoded responses (`"KEY": "value"`)
- `cli`: `shlex.split` uses `posix=False` on Windows to preserve backslash paths

## [0.1.0] — TBD

### Added
- `stdio` transport — spawn MCP server as subprocess, communicate via stdin/stdout JSON-RPC
- `MCPEnumerator` — discovers tools, resources, and prompts via `tools/list`, `resources/list`, `prompts/list`
- Module `tool-poisoning` (MCP01) — static analysis of tool descriptions for hidden instructions, suspicious unicode, and high-entropy obfuscation
- Module `schema-audit` (MCP09) — static audit of input schemas for weak definitions
- Module `param-injection` (MCP02) — schema-aware injection testing per parameter type
- Module `info-disclosure` (MCP04) — detects sensitive data leaked in tool responses
- Module `schema-bypass` (MCP05) — tests whether tools reject out-of-schema inputs
- `PayloadEngine` — classifies fields by name/description and selects appropriate payload set
- CLI: `corvus scan`, `corvus list-modules`, `corvus version`
- Report output: JSON + Markdown, OWASP MCP category per finding
- Mock vulnerable MCP server for integration tests
