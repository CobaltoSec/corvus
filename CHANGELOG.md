# Changelog

## [Unreleased]

## [RT-CORVUS-V16] — 2026-06-27 — Watchdog fix + Gap 1+3 detection

- **`stdio.py`** — `startup_timeout=45s`: watchdog task + kill-on-timeout en `send_request`; asyncio version parcial (threading.Timer pendiente para Windows ProactorEventLoop)
- **Gap 1 — `scope_audit.py`**: `_check_schema()` detecta credential fields (HIGH: `password`, `secret`, `jwt`, `api_key`, etc.) y PII fields (MEDIUM: `ssn`, `credit_card`, `medical_record`, etc.) en `inputSchema` de tools
- **Gap 3 — `endpoint_probe.py`**: 5 patrones naked credential value en `_TOKEN_SIGNALS`: `sk-proj-`, `AKIA[0-9A-Z]{16}`, `sk_live_`, `ghp_`, `xoxb-`
- **mock_server.py**: tools `tokenInputReceiver` (credential fields HIGH) + `customerDataProvider` (PII fields MEDIUM) + resource `api_keys.json` (naked keys)
- **Tests**: 160 → 164 (3 scope_audit inputSchema + 1 endpoint_probe naked keys)
- **CS02 scan**: bloqueado por watchdog asyncio inefectivo en Windows — diferido a fix threading.Timer

## [RT-CORVUS-V16-CS02-SETUP] — 2026-06-26 — CS02 Scan Infrastructure

- **targets-master.yaml** (CS02): 49 Tier D targets con nombres únicos derivados de scope npm — sin colisiones en output dirs
- **cs02.py**: CLI de scan/status/update/add para CS02 (fork de cs01.py, tier D support, 42 pending)
- **Skips documentados** (7): draw.io x2 (abren UI), fetcher-mcp/mcp-webresearch/mcp-screenshot (Playwright/Puppeteer), desktop-touch-mcp (OS automation), nx-mcp (cuelga buscando workspace Nx)
- **Bug identificado**: `StdioTransport` timeout 30s aplica al MCP handshake pero NO al startup del proceso — fix pendiente en `stdio.py`
- **Gap analysis malicious-mcp-server v1.5.0**: 3 gaps concretos en Corvus documentados (inputSchema credential harvesting MCP02, output_encoding módulo nuevo, resource content scan MCP01)
- **OWASP MCP Top 10 coverage**: 4 completos, 4 parciales, 1 by-design (MCP09), 0 sin módulo tras identificar gaps
- **Visión 30-40d**: documentada en SIGUIENTE.md — dataset 200+ servers, v1.0, arXiv, Ekoparty

## [RT-CORVUS-V15-CS02-SCRAPE] — 2026-06-26 — CS02 Target Discovery

- **scraper.py**: discovery npm registry (4 queries, 930 pkgs) + Smithery API (272 servers) → 84 candidatos threshold=200/wk
- **curate.py**: curaciación semántica 3 capas (SKIP_EXACT 90+/NAME 40+/DESC 8 patrones) + merge run1+run2 por varianza npm
- **candidates.yaml**: 84 candidatos brutos con metadata (downloads, version, has_bin, auth_required)
- **curated-keep.yaml**: 49 targets Tier D batchables (23 run2 + 26 run1-únicos)
- **curated-skip.yaml**: 61 descartados con razón explícita (audit trail)
- **tier-d-curated.yaml**: 49 entradas listas para targets-master.yaml — **72 servers totales al escanear**
- Ekoparty CFP relevado: abierto hasta 2026-08-14, probabilidad aceptación ~70-75%

## [RT-CORVUS-V14] — 2026-06-25 — E2E Final Dataset CS01

- **Re-scan**: 20 targets re-escaneados con Corvus v0.9.0 (`--redone` batch)
- **cs01.py**: flags `--redone` (re-scan done targets) + `--exclude` (skip targets por nombre)
- **findings-curated.md**: F52–F62 curados (11 findings nuevos: 7 TP + 4 FP); stats 51→62 total, 36→43 TP, 15→19 FP
- **report.md**: V14 completo — header v0.9.0, metodología 12→21 módulos, secciones server-sqlite/n8n-mcp/shell-servers/db-executeautomation actualizadas, stats table delta v0.8.1→v0.9.0, timeline disclosure
- **targets-master.yaml**: curation pending→TP/partial en todos los targets; corvus_version 0.9.0; notas V14 integradas
- **Delta V14**: shadow-tool "conflicts" variant (F56/F57/F58), scope-audit B0 quick win (F52/F53), endpoint-probe response_flood (F59/F62); FP DB shadow tools (F54/F55/F60/F61)

## [RT-CORVUS-V13] — 2026-06-25 — Detection Quality v0.9.0

- **B0a** — Encoding bypass: `%252e%252e%252f` (double-encode) + `．．／` (unicode fullwidth) en `traversal.yaml`
- **B0b** — Framework version string signal en `token_exposure.py` (`_SIGNALS`) → INFO finding para CVE targeting
- **B0c** — EXT02 INFO filter: `schema-audit` suprime "no required fields" para tools con nombre `search|query|list|get|doc|view|display|read` (~5 FPs CS01)
- **B0d** — `shadow-tool` escanea descriptions: keywords `executes|runs shell/command|subprocess|os.system|eval|popen` → HIGH finding
- **B1** — Nuevo módulo `ssrf.py` (EXT04): SSRF via URL/host params — content signal (metadata keywords) + timing signal; `EXT04_SSRF` en `OWASPCategory`
- **B2** — Nuevo módulo `endpoint-probe.py`: `resources/read` (traversal + SSRF + token exposure) + `prompts/get` (template injection `{{7*7}}` + prompt hijacking)
- **B3a** — `cmd-injection` extendido a params `integer` (SQL payloads) y `array` (traversal/injection payloads)
- **B3b** — Nuevo módulo `param-smuggling.py` (EXT01): hidden params `_debug/unsafe/admin/verbose/__proto__` + response diff
- **B3c** — Nuevo módulo `init-audit.py` (MCP07): control chars en `serverInfo` + protocol version downgrade probe
- **B3e** — Nuevo módulo `proto-fuzz.py` (EXT01): unknown methods + oversized method name + null ID probe
- **B5** — FP calibration: `rug-pull` downgrade a LOW para stateful tool names (`sequential_thinking/memory/session/context/chain`); `cmd-injection` skip SQL payloads para tools `write_query|execute_query|run_sql`
- **Tests**: 128 → 160 tests (+32); `mock_server.py` +resources/prompts handlers; `mock_ssrf_server.py` nuevo

## [RT-CORVUS-V13-DISC] — 2026-06-25 — Responsible Disclosure + Gap Analysis

- **Responsible disclosure completo**: 4 GHSAs creados en `CobaltoSec/advisories` + MSRC submitido
  - `GHSA-mf64-cgv4-ppcx` — `@playwright/mcp` path traversal (F33/F34, Microsoft MSRC + CVE pending)
  - `GHSA-7w27-7xwv-x6x2` — `mcp-server-sqlite` SQL injection (F29, modelcontextprotocol/servers)
  - `GHSA-7763-c5gf-v5fj` — `mcp-shell-server` injection (F42/F43, mako10k)
  - `GHSA-pr6r-h66r-m47j` — `server-everything` token exposure (F11, modelcontextprotocol/servers)
- **MSRC submission**: `@playwright/mcp` path traversal submitido con disclosure date Ekoparty 2026. Acknowledgement: Nicolas Padilla / CobaltoSec.
- **Gap analysis (3 agentes)**: identificados 8 gaps de detección — superficie MCP no testeada (`resources/read`, `prompts/get`), módulo SSRF faltante, encoding bypass, version string disclosure, hidden param fuzzing, initialize audit, sampling reverse channel, JSON-RPC fuzzing
- **SIGUIENTE.md**: RT-CORVUS-V13 (implementación completa) + RT-CORVUS-V14 (E2E final) definidos

## [RT-CORVUS-V12] — 2026-06-25 — CS01 Cierre + SSE fix + Tier C targets

- **CS01 cerrado**: 16 auditados (15 auto + 1 manual), 37 findings curados (F01–F37), 25 TP / 12 FP
- **SSE transport fix**: `Accept: application/json, text/event-stream` + `_parse_sse()` en `transport/http.py` — server-pdf ahora scaneable. 127/127 tests.
- **server-sqlite**: re-scan con `uvx mcp-server-sqlite` (npm 404 fix) — F29 SQL injection TP, F30 FP by design, F31/F32 schema bypass TP
- **server-postgres**: Docker postgres:15 test env — F35 supply chain TP (mismo advisory sdk)
- **server-pdf**: escaneado post SSE fix — 1 INFO (clean)
- **server-git**: Windows path fix (`C:/Temp/testrepo`) — 5 LOW schema quality (clean)
- **playwright-mcp F33/F34**: path traversal via `filename` params confirmado — `%2e%2e%2fetc%2fpasswd` creado en CWD durante scan batch anterior
- **report.md**: narrativa CS01 completa con secciones por server, patrones transversales, limitaciones de framework, stats finales
- **findings-curated.md**: sección estadísticas y tabla skips actualizadas (stale anterior eliminado)
- **Tier C targets**: 9 nuevos targets sin API key cargados en `targets-master.yaml` — 35 targets total, 9 pending para próximo bloque

## [RT-CORVUS-V11] — 2026-06-25 — CS01 Tier B scan + curation

- Poblado `targets-master.yaml` con 12 nuevos servers Tier B (8 scannable, 4 skip por creds)
- Batch scan Tier B ejecutado: 9 done, 4 errores resueltos
- 18 TPs confirmados (8 HIGH) — 62% servers con ≥1 HIGH finding
- `findings-curated.md` actualizado: F14–F28 (Tier B), notas de análisis por finding
- Finding notable: SSRF confirmado en `mcp-server-puppeteer` → navega a `169.254.169.254` (AWS metadata)
- Supply chain ecosistémico: `@modelcontextprotocol/sdk` advisory detectado en múltiples servers
- Diagnóstico de errores: `@modelcontextprotocol/server-fetch` es Python/uvx (no npm); `@jakenuts/mcp-cli-exec` no publicado
- `.gitignore` actualizado: excluye artefactos de scan (`%2e*`, `.playwright-mcp/`)

## [RT-CORVUS-V10] — 2026-06-24 — v0.8.0 OWASP Remap + B1/B2 CS01

### Breaking changes (SARIF rule IDs and module names changed)

**OWASP ID remap completo — alineado con OWASP MCP Top 10 oficial**

| Módulo | ID anterior | ID correcto | Cambios |
|--------|-------------|-------------|---------|
| `token-exposure` (ex `info-disclosure`) | MCP04 | MCP01 | Renombrado + remap |
| `scope-audit` | MCP02-SCOPE | MCP02 | Limpieza sufijo |
| `tool-poisoning` | MCP01 | MCP03 | Solo remap |
| `supply-chain` | MCP04-SUPPLY | MCP04 | Limpieza sufijo |
| `cmd-injection` (ex `param-injection`) | MCP02 | MCP05 | Renombrado + remap |
| `rug-pull` | MCP06 | MCP06 | Sin cambio |
| `auth-audit` | MCP08 | MCP07 | Solo remap |
| `log-audit` | MCP10 | MCP08 | Solo remap |
| `response-flood` | MCP07 | MCP10 | Solo remap |
| `schema-bypass` | MCP05 | EXT01 | Moved to extension |
| `schema-audit` | MCP09 | EXT02 | Moved to extension |
| `shadow-tool` | MCP03 | EXT03 | Moved to extension |

- Nuevos archivos: `token_exposure.py` (ex `info_disclosure.py`), `cmd_injection.py` (ex `param_injection.py`)
- SARIF rule IDs usan nuevo scheme: `CORVUS-MCP01` → token-exposure, `CORVUS-MCP03` → tool-poisoning, etc.
- `OWASPCategory` enum reescrito con nombres canónicos y valores correctos
- Nuevo test `tests/test_owasp_remap.py` (12 parametrizados) verifica IDs post-remap

**B1 — Supply Chain FP fix**
- Cascade advisories (via=list de strings) ahora filtrados — no son vulnerabilidades directas
- Findings sin CVE asignado: confidence reducida de 90 → 65
- CS01-F10 (`server-github@*`): retroactivamente marcado como FP (cascade)
- CS01-F09 (`@modelcontextprotocol/sdk@<=1.25.1`): TP con confidence=65
- +2 tests en `test_supply_chain.py`

**B2 — server-pdf investigation**
- Diagnóstico: `@modelcontextprotocol/server-pdf` es HTTP server (porta 3001), no stdio
- Target corregido en `targets-cs01-tier-a.yaml`: `transport: http, url: http://localhost:3001/mcp`
- Requiere startup manual antes de batch

**Tests: 111 → 125 (+14)**
- +2 supply chain tests (cascade + no-CVE confidence)
- +12 remap tests parametrizados (`test_owasp_remap.py`)

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
