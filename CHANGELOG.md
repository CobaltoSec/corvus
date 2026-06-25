# Changelog

## [Unreleased]

## [RT-CORVUS-V09] — 2026-06-25

### Added — MCP02 scope-audit + MCP04 supply-chain + CS01 Batch Tier A

**MCP02 — `scope_audit.py` (nuevo módulo estático)**
- Detecta privilege escalation via scope creep en tool names y descriptions
- HIGH: nombre contiene `admin`/`root`/`superuser`/`elevated`/`privileged`
- HIGH: description contiene `unrestricted access`/`without restriction`/`full access`/`any path`/`all files`
- MEDIUM: nombre con prefijo read-only (`read_`/`get_`/`fetch_`/`list_`) pero description menciona escritura
- MEDIUM: keywords `override`/`escalate`/`all_access`/`unlimited` en description
- Registrado en `_ALL_MODULES` y `_STATIC` (cli.py + batch.py)

**MCP04 — `supply_chain.py` (nuevo módulo estático)**
- Pre-scan: extrae package npm del cmd stdio, crea tmpdir, `npm install --package-lock-only`, `npm audit --json`
- Mapeo de severidad: `critical` → CRITICAL, `high` → HIGH, `moderate` → MEDIUM
- Solo aplica a transport=stdio con comandos npx/npm; HTTP y non-npm → skip
- `_run_npm_audit()` separada para monkeypatching en tests
- Fix Windows: `shutil.which("npm")` resuelve `npm.cmd` en lugar de `npm` bare
- Registrado en `_ALL_MODULES` y `_STATIC`

**Tests: 97 → 111 (+14)**
- 2 E2E tests `scope_audit` en `test_modules.py`
- 12 tests `supply_chain` en `test_supply_chain.py` nuevo (5 unit helpers + 4 E2E monkeypatched + 3 negativos)
- `tests/mock_server.py`: +`admin_read_all` (HIGH scope creep), +`read_config` (clean, negativo)

**Bug fix — `batch.py` summary_md**
- `sum(finding_count.values())` crashaba cuando un target fallaba con `{"error": str(e)}`
- Fix: detecta key `"error"` y muestra `ERROR` en la tabla en lugar de crashear
- `session.target` corregido a `" ".join(target.cmd)` (antes era solo `cmd[0]`)

**CS01 Batch Tier A**
- `case-studies/cs01-mcp-ecosystem/targets-cs01-tier-a.yaml` — batch config (server-github, server-pdf, server-everything)
- `server-github v0.6.2`: 2 HIGH supply chain (`@modelcontextprotocol/sdk` + `server-github` advisories)
- `server-everything`: 13 findings (1H info-disclosure get-env + 2M + 6L + 4I schema issues)
- `findings-curated.md` actualizado: CS01-F09 a F13 agregados, totales actualizados

**env**
- `GITHUB_TOKEN` agregado a `.env`

## [0.7.0] — 2026-06-25

### Added — RT-CORVUS-V08: Detection Quality + Batch Scan

**A1 — Batch Scan Mode**
- New `corvus batch targets.yaml` CLI command — scan multiple MCP servers in one invocation
- `BatchTarget` model: name, transport, cmd/url per target
- Per-target output directories with individual `report.json`/SARIF; top-level `summary.md` (Markdown table)
- `--min-confidence`, `--fail-on`, `--sarif`, `--output-dir` flags pass through to each scan
- New module: `corvus/batch.py` (`load_batch_targets`, `run_batch`, `BatchResult`)

**A2 — Confidence Score**
- `Finding.confidence: int = 50` (0-100) — added to all findings across 10 modules
- Canonical values: exploitation_confirmed → 95, SQL error confirmed → 92, rug_pull appeared → 90, shadow tool name → 90, regex/keyword match → 85, schema presence → 80, traversal unconfirmed → 50, JSON key echo → 30, entropy signal → 20
- New `--min-confidence N` flag in both `corvus scan` and `corvus batch` — filters findings before writing report

**A3 — Entropy Threshold Fix**
- `tool_poisoning`: Shannon entropy threshold raised `4.5 → 5.0`; guard added: only check entropy if `len(description) > 200` — eliminates FPs on short base64 identifiers

**A4 — Error-Provoking Info-Disclosure**
- `info_disclosure`: now probes each tool with (1) missing required args `{}` and (2) oversized 10k-char string, in addition to the standard benign call — surfaces stack traces and error messages that only appear under bad input

**A6 — HTML Catch-All FP Filter**
- `info_disclosure`: responses starting with `<!DOCTYPE` or `<html` are skipped — eliminates FPs on HTTP servers returning SPA index pages for every route

**A7 — Rug Pull Stateful FP Fix**
- `rug_pull`: if second `tools/list` returns empty list (not shrunken, but zero tools), no finding is emitted — eliminates FP on stateful servers like `server-sequential-thinking`

**A9 — listChanged Retry**
- `enumerator`: if server declares `capabilities.tools.listChanged = true` and first `tools/list` returns empty, waits 2s and retries once — covers servers like `server-everything` that populate tools asynchronously

**M1 — SQL Error-Based Injection Confirmation**
- `param_injection`: detects `sqlite3.OperationalError`, `SQLSTATE`, `syntax error near`, etc. in response → upgrades to CRITICAL + `exploitation_confirmed = True` (confidence = 92)

**M2 — Deny-In-Context Severity Downgrade**
- `param_injection`: if reflected payload response contains "sanitized", "filtered", "escaped", or "blocked" → downgrade to LOW (confidence = 30) instead of HIGH

**M3 — CORVUS_PROXY Env Var**
- `HttpTransport`: reads `CORVUS_PROXY` env var and passes to `httpx.AsyncClient(proxy=...)` — enables routing through Tor, Burp, or upstream proxy without CLI changes

### Tests
- 78 → 97 tests (+19 across `test_modules_v5.py`, `test_enumerator_listchanged.py`, `test_batch.py`, `test_transport_http.py`)

## [RT-CORVUS-V06b] — 2026-06-24

### Added — C1/C2/C3 Framework Improvements
- **C1 Request/Response Capture**: `RawExchange` model, `log_requests=True` en ambos transports, `--log-requests` CLI flag escribe `exchanges.jsonl` junto al reporte
- **C2 Startup Validation**: `ServerStartupError` con contenido de stderr cuando un server crashea antes del primer request (300ms crash detection). Fix Windows: `shutil.which()` detecta `.cmd`/`.bat` scripts y usa `create_subprocess_shell` automáticamente
- **C3 Exploitation Confirmation**: `_traversal_confirmed()` detecta firmas de contenido real (`root:x:0:0`, `HOME=`, etc.) independientemente de reflection — CRITICAL sin echo; traversal unconfirmed → MEDIUM
- **A5 Windows payloads**: `PayloadEngine.get_payloads("path")` incluye sección `windows` de `traversal.yaml` en `sys.platform == "win32"`
- Tests: 64 → 78 (+14: 4 C1, 3 C2, 7 C3)

### Added — CS01 First Real Scans
- `case-studies/cs01-mcp-ecosystem/` con methodology, targets, findings-raw y findings-curated
- 4 servers oficiales `@modelcontextprotocol` escaneados:
  - `server-filesystem 0.2.0`: 3 HIGH MCP03 (shadow tool: read_file/write_file/edit_file)
  - `server-memory 0.6.3`: 9 LOW MCP05 (schema bypass, sin `additionalProperties: false`)
  - `server-sequential-thinking 0.2.0`: 1 HIGH MCP06 rug pull (FP stateful) + 2 MCP01 FPs
  - `server-everything 2.0.0`: 0 tools (usa `listChanged` dinámico — gap de cobertura documentado)
- 5 TRUE POSITIVES confirmados, 3 FP identificados con candidatos de fix (A7/A9)

## [0.5.1] — 2026-06-12

### Fixed
- `schema-bypass` (MCP05): false positives on pydantic v2-based MCP servers — `_accepted()` now
  checks for `isError: true` in the tool result, so validation failures (missing required fields)
  are correctly treated as rejections rather than successes. This eliminates ~10 spurious MEDIUM
  findings per tool with a required field (e.g. kestrel-mcp, llamascope-mcp).
- `param-injection` (MCP02): two false-positive patterns eliminated:
  1. Payloads echoed inside error responses (`isError: true`) are no longer reported at all.
  2. Payloads reflected as a named JSON field in the result (e.g. `{"host": "<payload>"}`) are
     downgraded from HIGH to LOW — tools that log their own inputs are not injection vectors.

### Added
- README: CLI Reference section with full `corvus scan --help` flag reference and `list-modules`
  / `version` command examples.

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
