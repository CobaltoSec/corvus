# Changelog

## [Unreleased]

## [RT-CORVUS-V06] — 2026-06-08

- PyPI publish `cobaltosec-corvus==0.5.0` — live en https://pypi.org/project/cobaltosec-corvus/0.5.0/
- E2E contra kestrel-mcp (74 tools): 28 static findings (entropy) + 27 HIGH injection reflections + schema bypass masivo
- E2E contra llamascope-mcp (10 tools): 3 LOW static + 6 HIGH injection reflections + schema bypass
- README completo: 10 módulos, transports HTTP/stdio, corvus.toml, plugin system, SARIF, CI examples

## [0.5.0] — 2026-06-08

### Added
- **Config file support** (`corvus.toml`) — define targets, modules, headers, timeout, SARIF,
  and plugin directories without repeating CLI flags. Load with `--config path/to/corvus.toml`.
  Merge semantics: CLI args override config; config fills what CLI omits.
- **Plugin system** — external scan modules loadable from two sources:
  - `--plugin-dir <path>` (or `scan.plugin_dirs` in config): loads `*.py` files defining
    `ScanModule` subclasses from any directory; malformed files are silently skipped
  - `entry_points` group `corvus.modules`: pip-installable plugins registered via
    `project.entry-points."corvus.modules"` in the plugin package's pyproject.toml
  - Plugins override built-in modules of the same name (enables built-in replacement)
- `list-modules --plugin-dir <path>` now shows a **Source** column (built-in / plugin)
- `pydantic`-validated config model (`corvus.config.CorvusConfig`) exported for programmatic use

### Changed
- CLI `--transport`, `--module`, `--timeout` are now `Optional` (default `None`); value falls
  back to config file, then to built-in defaults. Behaviour is unchanged when no config is used.

## [0.4.0] — 2026-06-08

### Added
- Module `log-audit` (MCP10) — completes OWASP MCP Top 10 coverage; static analysis that detects
  tools capable of destroying the audit trail (CRITICAL — anti-forensic risk) or exposing raw
  log data (HIGH — logs commonly contain credentials, session tokens, and PII)
- SARIF 2.1.0 output via `--sarif` flag; produces `report.sarif` alongside the JSON+Markdown
  reports, compatible with GitHub Advanced Security and any SARIF-aware CI tool
- `--header "Key: Value"` CLI option for HTTP transport (repeatable); enables Bearer token and
  API key authentication against protected MCP servers
- GitHub Actions CI (`.github/workflows/ci.yml`) — pytest + ruff lint on Python 3.11 and 3.12

### Changed
- Mock server has two new vulnerable tools: `clear_audit_log` (MCP10 CRITICAL) and
  `get_access_log` (MCP10 HIGH) for integration test coverage
- `_ALL_MODULES` now lists 10 modules (full OWASP MCP Top 10)

## [0.3.0] — 2026-06-08

### Added
- Module `response-flood` (MCP07) — detects tool responses exceeding 8 KB (HIGH) or
  containing highly repetitive trigrams (MEDIUM) that could flood an LLM context window
- Module `auth-audit` (MCP08) — static analysis that flags tools explicitly claiming no
  authentication, marked as admin/internal-only without auth enforcement, or using
  restricted-access naming conventions (admin_, internal_, debug_)
- HTTP transport integration tests (`test_transport_http.py`) using a thread-based
  in-process mock HTTP server (`mock_http_server.py`)
- Mock server tools: `get_config` (MCP07 vulnerable — returns ~20 KB payload) and
  `admin_reset` (MCP08 vulnerable — "No authentication required" in description)
- `OWASPCategory.MCP07_RESPONSE_FLOOD` and `MCP08_AUTH_BYPASS` enum values
- `test_discovery.py` now uses `>= 6` instead of hardcoded count for maintainability

## [0.2.0] — 2026-06-08

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

## [0.1.0] — 2026-06-08

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
