# Changelog

## [1.0.1] — 2026-07-01

- **Windows noise fix** — supresión de `socket.send() raised exception` y `_ProactorBasePipeTransport.__del__` ValueError en batch scan Windows (asyncio exception handler + sys.unraisablehook en `batch.py`/`cli.py`). `stdio.py` cierra stdin antes de `terminate()`. Sin cambios de API ni módulos.

## [RT-CORVUS-V23] — 2026-07-01 — E2E scan v1.0.0 + Windows noise fix

- **PyPI v1.0.0** publicado + GitHub release v1.0.0 con release notes
- **Windows noise fix** — `batch.py` + `cli.py`: custom asyncio exception handler silencia `socket.send() raised exception`; `sys.unraisablehook` filtra `_ProactorBasePipeTransport.__del__` ValueError. `stdio.py`: cierra `stdin` antes de `terminate()` para reducir broken-pipe events en origen
- **C1 E2E** — re-scan 53 servers (CS01: 22, CS02: 31) con v1.0.0; nuevos findings capturados de EXT06/EXT07 en `mcp-server-fetch`, `playwright-mcp` (+3H), `remnux-mcp-server` (+2H +6M), `docx-mcp` (+2H)
- **targets-master.yaml** CS01 + CS02 actualizados con resultados del scan v1.0.0

## [1.0.0] — 2026-06-30

22 módulos (10 static + 12 dynamic), 351 tests, API pública estabilizada (`py.typed`, `__all__`).
Dataset CS01+CS02: 54 servers auditados, 72 TPs, 3 CRITICAL. 6 GHSAs submitidas.

## [RT-CORVUS-V22] — 2026-06-30 — Python supply chain + response injection + API v1.0

### B2 — MCP04 Python Supply Chain
- **`supply_chain_python.py`** — nuevo módulo `supply-chain-python` (static, MCP04). Extrae package de `uvx`/`uvx --from`/`uv run --with`/`uv tool run` y corre `pip-audit -r requirements.txt --format json`. HIGH con CVE (confidence 90), MEDIUM sin CVE (confidence 65). Guard silencioso si `pip-audit` no está instalado.
- **`tests/test_supply_chain_python.py`** — 24 tests: extracción de package (uvx/uv variantes, extras strippeados), parse pip-audit JSON, integración con mocks. Fix: split en `[_-]` para word boundaries con underscores.
- **`cli.py`** — registro `supply-chain-python` en `_ALL_MODULES` + `_STATIC`.

### B1 — EXT07: Prompt Injection via Response (MCP10)
- **`response_injection.py`** — nuevo módulo `response-injection` (dynamic, MCP10). Llama cada tool con args benignos y escanea la respuesta por LLM-directive language. Tier 1 (HIGH, todos los tools): ignore-previous-instructions, disregard, forget, override-system-prompt. Tier 2 (MEDIUM, solo non-web): you-are-now, as-a-new-ai, true-purpose, do-not-follow. Delimiters fake `[SYSTEM]`/`[INST]`/`<|im_start|>` → CRITICAL. Web tool detection por split de nombre en `[_-]` + frozenset + desc regex. Un finding por tool (highest sev), todos los labels en evidence. Cap 16KB.
- **`tests/test_response_injection.py`** — 34 tests: `_is_web_tool`, `_scan_text` por tier y tipo de tool, integración con mocks (detection, CRITICAL, lower-sev-web, clean, exception, empty).
- **`cli.py`** — registro `response-injection` en `_ALL_MODULES` + `_DYNAMIC`.

### B3 — API pública v1.0
- **`corvus/__init__.py`** — `__all__` con 10 símbolos públicos (`Finding`, `Severity`, `OWASPCategory`, `ScanModule`, `ScanResult`, `MCPSurface`, `ToolSpec`, `ResourceSpec`, `PromptSpec`, `RawExchange`). Version dinámica via `importlib.metadata` (fix: antes hardcodeada como "0.9.0").
- **`corvus/py.typed`** — marker PEP 561 vacío. Type checkers (mypy/pyright) reconocen el paquete como typed.
- **`pyproject.toml`** — classifier Alpha→Production/Stable, + Python 3.12, + `Typing :: Typed`. Package-data `"corvus" = ["py.typed"]`.
- **`tests/test_public_api.py`** — 23 E2E tests de contrato: importabilidad de `__all__`, py.typed presente, Severity/OWASPCategory valores, Finding construcción y JSON roundtrip, ScanResult.finding_count, ScanModule subclassing y ejecución, abstract no instanciable.

### Totales
- Tests: 270 → 351 (+81). 22 módulos. Suite completo: 351/351 pass.

## [RT-CORVUS-V21] — 2026-06-30 — FP calibration v4 + mejoras + 2 módulos nuevos

### A1 — FP calibration v4 (5 fixes)
- **`shadow_tool.py`** — C1: `_QUERY_VERB_TOOL_RE` — tools `read_query`/`write_query`/`execute_sql`/`run_query`/`execute_statement`/`run_dml`/etc. bajan a MEDIUM en descripción (no HIGH). Excluye `command` suffix para evitar suprimir `execute_command`.
- **`rug_pull.py`** — C2: `_STATEFUL_TOOL_NAME` usa `sequential.?thinking` en vez de `sequential_thinking` — cubre `sequentialthinking` (sin separador) y `sequential-thinking` (guión).
- **`response_flood.py`** — C3: `_ADMIN_LIST_TOOL_RE` — `get_whitelist/blacklist/allowlist/blocklist/config/settings` se skipean (admin config dumps no son flood). Agrega `import re`.
- **`cmd_injection.py`** — D2: `_OS_ERROR_SIGNATURES` + `_os_error_traversal_confirmed()` — ENOENT/Permission denied/FileNotFoundError en respuesta a payload de traversal → HIGH confirmado (nivel inferior a CRITICAL para file content leak).
- **`scope_audit.py`** — D5: `_ENV_DUMP_TOOL_RE` — `get-env`/`list_env`/`dump_environment`/`export_env_vars`/etc. → HIGH automático. Check antes de `_HIGH_NAME_SCOPE`.
- **`tests/mock_server.py`** — renombrado `get_config` → `dump_telemetry` (colisionaba con C3 skip).
- **`tests/test_modules_v3.py`** — test `test_response_flood_detects_oversized` actualizado a `dump_telemetry`.
- **`tests/test_fp_calibration_v4.py`** — 34 nuevos tests (C1/C2/C3/D2/D5).

### A2 — Mejoras módulos existentes
- **`scope_audit.py`** — D1: `_check_write_traversal()` — si tool tiene param `filename`/`file_path`/`output_path`/`save_to`/`dest` AND descripción implica write intent (save/write/export/dump) → HIGH (confidence 65, manual verification). Cubre CS01-F33/F34 class (playwright-mcp `browser_snapshot.filename`).
- **`ssrf.py`** — D4: `_URL_DESC` regex — si descripción del tool contiene `navigate/browse/fetch/request/scrape/crawl/http/download/visit`, TODOS los params string se tratan como candidatos URL. Cubre CS01-F14 (puppeteer `navigate`).

### A3 — Módulos estáticos nuevos
- **`corvus/modules/static/resource_uri.py`** — EXT05: escanea `resources/list` URIs por patterns sensibles: CRITICAL para `.ssh/`/`/etc/shadow`/`.env`/`.aws/credentials`/`private_key`/etc., HIGH para `file://` fuera de `/tmp`+`/var/app` y credential query params (`?token=`, `?api_key=`), MEDIUM para >20 recursos expuestos.
- **`corvus/modules/static/tool_chaining.py`** — EXT06: detecta descripciones que referencian otros tools del mismo server con lenguaje imperativo (`must call X`, `always invoke Y`, `failure to invoke Z`) → MEDIUM; compliance language (`violates security policy`, `non-compliant`) eleva a HIGH.
- **`corvus/core/models.py`** — `EXT05_RESOURCE_URI` + `EXT06_TOOL_CHAINING` en `OWASPCategory`.
- **`corvus/cli.py`** — registro de `resource-uri` + `tool-chaining` en `_ALL_MODULES` y `_STATIC`.
- **`tests/test_modules_v7.py`** — 35 nuevos tests (D1/D4/EXT05/EXT06).

### Totales
- **Módulos**: 18 → 20
- **Tests**: 201 → 270 (+69)

## [RT-CORVUS-V20] — 2026-06-29 — FP calibration v3

- **`cmd_injection.py`** — `_ECHO_FIELD_NAMES` expandido con 17 términos de dominio (color, coin, domain, markdown, phone, org, vs, url, format, content, value, data, message, code, source, html, param). Nuevo `_TRANSFORMATION_TOOL_RE`: si el nombre del tool contiene verbos de transformación (format, convert, encode, render, etc.), cualquier reflejo del input se trata como echo display, no señal de inyección. `_is_input_echo()` recibe `tool_name` como parámetro. Fix CS02-FP03 class (10+ FPs en myclaw-toolkit).
- **`token_exposure.py`** — `_is_type_annotation_match()` extendido: template literal types (`` `${string}` ``), array shorthand (`string[]`), TS modifier words (readonly, optional, abstract, static, etc.). Nueva función `_strip_code_blocks()`: elimina bloques de código markdown (``` ``` ``` y `` `...` ``) antes de escanear credenciales, evitando FPs en respuestas de documentación técnica. Fix CS02-FP01/FP02 residuales.
- **`shadow_tool.py`** — Scope qualifier severity reducer: si `_check()` detecta un nombre EXACT_HIGH pero la descripción contiene un qualifier de alcance ("only", "within", "restricted to", etc.), downgrade HIGH → MEDIUM. DB-prefix description downgrade: `_check_description()` emite MEDIUM (no HIGH) para tools con prefijo de DB (`pg_`, `mysql_`, `mongo_`, etc.) que usan lenguaje de ejecución en su descripción. Fix CS02-FP04/FP05 class.
- **`param_smuggling.py`** — `_response_diff()` refactorizado: (1) early exit cuando probe causa `isError=True` — el server rechazó el param desconocido (comportamiento CORRECTO, no backdoor); (2) skip cuando los nuevos JSON keys son solo indicadores de error (`error`, `errors`). Fix CS02-F13/F14 class FPs (lsp-mcp-server, jamf-docs-mcp-server).
- **`tests/test_fp_calibration_v3.py`** — 21 nuevos tests cubriendo todas las calibraciones.
- **`pyproject.toml`** — bump 0.9.2 → 0.9.3
- **Tests** — 180 → 201

## [RT-CORVUS-V19] — 2026-06-29 — CS02 segunda pasada + responsible disclosure

- **`corvus/transport/stdio.py`** — `env_vars` support: `StdioTransport.__init__` acepta `env: dict[str,str] | None`, merged sobre `os.environ` en `connect()`.
- **`corvus/batch.py`** — `BatchTarget.env_vars`, `load_batch_targets` parsea `env_vars` de YAML, `_TARGET_SCAN_TIMEOUT` 120s → 600s, `run_batch()` acepta `target_timeout` param.
- **`corvus/cli.py`** — `batch` command: `--target-timeout` CLI option.
- **`case-studies/cs02-mcp-ecosystem/cs02.py`** — `--target-timeout` propagado al batch scan.
- **`targets-master.yaml`** — 22 targets error investigados y resueltos: 6 skip definitivos, resto re-escaneados. Estado final: 31 done / 18 skip / 0 pending.
- **`findings-curated.md`** — F15-F31 agregados (segunda pasada): 2 CRITICAL (malicious-mcp-server resource exposure, remnux-mcp-server cmd injection), 15 HIGH (SSRF, shadow tools, supply chain, output encoding).
- **`report.md`** — Actualizado con números finales (31 scaneados, 29 TPs, combined dataset 54 servers / 72 TPs), sección Responsible Disclosure con 2 nuevos GHSAs.
- **Responsible disclosure** — GHSA-43j9-hmpq-cgv7 (remnux-mcp-server CRITICAL, lennyzeltser notificado) + GHSA-qwwj-38wj-ffvw (myclaw-toolkit SSRF, Dusheh notificado). 90d timeline.

## [RT-CORVUS-V18] — 2026-06-28 — FP calibration v2 (plain-text echo + TS primitives)

- **`cmd_injection.py`** — `_is_input_echo()` extendido a plain-text: si el param está en `_ECHO_FIELD_NAMES` (query, search, term, etc.) y el payload aparece en una respuesta plain-text → LOW en lugar de HIGH. Cubre search tools que no retornan JSON.
- **`token_exposure.py`** — `_is_type_annotation_match()` extendido con `_TS_PRIMITIVE_TYPES` (string, boolean, number, null, undefined, void, never, any, unknown, object) y detección de union/intersection types (`|`, `&`). Cubre `TOKEN: string`, `SECRET: boolean | null`.
- **`pyproject.toml`** — bump 0.9.1 → 0.9.2
- **Tests** — 174 → 180 (+3 cmd_injection plain-text echo + 3 token_exposure primitivos/union)

## [RT-CORVUS-V17] — 2026-06-28 — FP calibration + README research section + v0.9.1

- **`token_exposure.py`** — A2: `_is_type_annotation_match()` filtra TypeScript type annotations (`MaybeRefOrGetter<boolean>`, `Ref<string>`) que matcheaban el regex de credential pero no son credenciales reales. Fix para CS02-FP01/FP02 (regle-mcp-server Vue.js docs).
- **`cmd_injection.py`** — A3: `_is_json_key_echo` → `_is_input_echo` expandido con `_ECHO_FIELD_NAMES` frozenset (query, search, symbol, term, etc.). Cubre el caso donde el field name del echo ≠ param name (CS02-FP03: 10 targets con search tools).
- **`README.md`** — Overhaul completo: badges (PyPI/CI/Python), versión v0.9.1, tabla 18 módulos (static 7 + dynamic 11 con OWASP IDs correctos), sección "Research: MCP Ecosystem Security Audit" (CS01+CS02 combined dataset, 4 GHSAs, 65% servers con ≥1 HIGH).
- **`pyproject.toml`** — bump 0.9.0 → 0.9.1
- **Tests** — 169 → 174 (+3 A2 token_exposure calibration + 2 A3 cmd_injection calibration)

## [RT-CORVUS-V16b] — 2026-06-28 — CS02 scan completo + Gap 2 + watchdog Windows fix

- **`stdio.py`** — watchdog real para Windows: `threading.Timer` + `_kill_process_tree()` (taskkill /F /T mata árbol de procesos node/cmd); `asyncio.create_task` no funcionaba en ProactorEventLoop bloqueado por `readline()`; startup check timeout 0.3→2.0s (Python startup Windows)
- **`batch.py`** — 22 módulos sincronizados (5 faltaban: ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz + output-encoding); `asyncio.timeout(120)` por target como safety net; `_TARGET_SCAN_TIMEOUT=120`
- **Gap 2 — `output_encoding.py`**: detector invisible/dangerous Unicode — control chars (HIGH), zero-width chars (HIGH), bidi overrides (CRITICAL); regexes construidas con `chr()` para evitar literales invisibles
- **`mock_server.py`**: tool `stealth_formatter` con payload `\x00 + U+200B + U+202E` para tests output_encoding
- **Tests**: 164 → 169 (5 nuevos output_encoding)
- **CS02 batch scan** — 20/42 targets exitosos; 22 startup errors (credenciales/config required); 7 skip; 257 raw findings
- **findings-curated.md CS02**: 14 findings (10 TP HIGH: shadow-tools/proto-crash/scope-creep/supply-chain/response-flood; 4 FP: token-exposure docs, injection echo)
- **report.md CS02**: análisis completo — 35% servers vulnerable a protocol crash, Gap 1 detección automática confirmada, FP rate 40%, recomendaciones de calibración
- **`.gitignore`**: batch-scans CS02 + artifact files de scan (path traversal, upg, null bytes)

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
