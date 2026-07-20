# Changelog

## [RT-CORVUS-CS16] — 2026-07-20 — CS16: 134 HTTP targets (Petrel Run 2) · 3 GHSAs · 315 servers

- **CS16 — Petrel Run 2 HTTP scan (134 targets)** — `corvus batch` concurrency 5, todos los módulos, SARIF. 15/134 OK (11%), 119 ERROR/auth/offline. 188 raw findings, ~16 TPs. FP rate 91.5% (esperado para internet-facing; petrel-critical/no-auth pre-filter 59% conversion).
- **GHSA-7rqv-4g54-hcxh — glimind-oracle SSRF CRITICAL** — `watch_tool` acepta URLs link-local y RFC-1918 sin validación. 3 vectores confirmados (toolId/webhook/minSeverity) → AWS IMDS (ami-id/instance-id) + Alibaba Cloud IMDS. IAM credential chain exploitable vía `/iam/security-credentials/`. CVSS 8.6. No auth required.
- **GHSA-j62x-hg79-www6 — FinanceMCP XSS ×4 HIGH** — `finvestai.top`: inputs de stock_data/index_data/macro_econ reflejados verbatim en mensajes de error de Tushare API.
- **GHSA-hx6w-3q3r-h3j8 — omi.me injection + EXT11 HIGH** — `storefront-renderer`: prompt injection via `update_cart.note` + `logging/setLevel` unauthenticated accepted → customer PII en logs.
- **public-stats.yaml** — 315 servers (+15), 53 GHSAs (+3), 4,190 raw findings (+188), ~1,314 TPs (+16). CS16 entry added.
- **744 tests pass** (sin regresiones).

## [RT-CORVUS-IMPROVE-1] — 2026-07-17 — Pre-Run 2 fixes: response_flood 32KB gate + schema_bypass behavioral diff + batch CLI flags

- **D1 — response_flood.py FP reduction (60-70% en data tools)** — Agregado `_DATA_TOOL_RE` (search|query|fetch|retrieve|get|list|read|find|lookup|scrape|extract|parse|download|load|index) con `_SIZE_THRESHOLD_DATA = 32_768` (32KB). Data tools reciben 4× el threshold default (8KB), eliminando la mayoría de FP LOWs en HF Spaces/Gradio donde respuestas grandes son esperadas.
- **D2 — schema_bypass.py behavioral diff gate para `__proto__`** — Test 3 (prototype pollution) ahora requiere diff de comportamiento: baseline vs respuesta con `__proto__`. Solo flagea si la respuesta cambia. Nuevo método `_response_str()`. Elimina ~20-40 LOW FP por target donde el server ignora correctamente campos desconocidos.
- **D3 — `corvus batch` CLI: `--skip-existing` + `--case-study`** — Ambos flags ya estaban wired en `run_batch()` pero no expuestos en el CLI. Ahora visibles en `corvus batch --help`. Habilita runs reanudables y tagging de case study (e.g. `--case-study CS16`).
- **Fix — test_discover.py PYPI_CURATED size** — `test_pypi_search_by_name_filters_mcp` usaba `range(30)` hardcodeado pero PYPI_CURATED creció de 25 a 37 entradas; `30 > 37` → False → fallback. Cambiado a `len(_discover.PYPI_CURATED) + 10`.
- **Fix — test_fp_calibration_v4.py tool name** — `search_everything` matcheaba `_DATA_TOOL_RE` vía "search" substring, haciendo que el mock de 10KB cayera bajo el nuevo threshold de 32KB. Cambiado a `process_request` (non-data tool, preserva la intención del test).
- **744 tests pass** (sin regresiones).

## [RT-CORVUS-ROADMAP-ANALYSIS] — 2026-07-13 — Análisis multi-agente + roadmap de mejoras

- **Análisis 5 dominios en paralelo** — scanner/FP calibration, discovery pipeline, disclosure management, CLI/DX, y estrategia post-CFP. 28 mejoras identificadas y clasificadas en 4 fases por esfuerzo/impacto.
- **Roadmap publicado** — artifact interactivo con fases, prioridades y detalles de implementación por dominio: https://claude.ai/code/artifact/bc3474cb-e294-41e3-90a6-164f257e0fa4
- **RT-CORVUS-IMPROVE-1 documentado** — SIGUIENTE.md actualizado con el plan completo de mejoras (Fase 1 XS → Fase 4 Estratégico).
- **Hallazgos clave**: scope-part dedup bug activo en discover.py (bloquea orgs completas), response_flood.py es el mayor FP driver (60-70% en data tools), 21 GHSAs de CS12-CS15 sin documentar en DISCLOSURE-PROCESS.md, arXiv paper al 90% ready.

## [RT-CORVUS-GHSA-CREDITS] — 2026-07-07 — Credits nicoPadi1002 en todos los GHSAs

- **Batch-patch 55 GHSAs** — 52 drafts + 3 published: todos actualizados vía `gh api PATCH` para creditar `nicoPadi1002` como `reporter`. GitHub permite editar credits en advisories publicados (no documentado explícitamente).
- **DISCLOSURE-PROCESS.md actualizado** — payload de creación de advisory ahora incluye `"credits": [{"login": "nicoPadi1002", "type": "reporter"}]` por defecto. Todo GHSA futuro ya nace con el crédito correcto. Protocolo de lookup de contacto documentado: 3 pasos (npm metadata + owner type + top committers), estrategia de invitar ≥2 contactos distintos por GHSA.
- **Decisión de marca** — reporter = nicoPadi1002 (brand personal, estándar industry: CVEs/GHSAs siempre crédito individual); advisory hosteado en CobaltoSec/advisories (brand org). Setup idéntico a Google Project Zero.

## [RT-CORVUS-CFP-FINAL] — 2026-07-06 — CFP Ekoparty 2026 submitteado · 300 servers · 44 GHSAs

- **CFP submitteado en Sessionize** — "Corvus: Seguridad en el Ecosistema MCP a Escala" enviado a Ekoparty Security Conference 2026 Buenos Aires (Oct 7–9). Primera ronda de notificaciones: 2026-09-04.
- **Stats finales del submission** — 300 servers (CS01–CS15), 4,002 raw findings, ~1,298 TPs, 44 GHSAs (3 publicados, 41 draft), 34 módulos, 717 tests, v1.3.1.
- **Materials actualizados** — `cfp-ekoparty-2026.md` (abstract + descripción detallada + outline 30min + bio + corrección "dos meses"), `technical-paper-ekoparty-2026.md` (CS11–CS15 dataset rows + findings §4.8–4.10: healthcare/XSS cluster/template cascade + FP cal v3). Slides deck: 18 slides actualizados (300/4,002/~1,298/44). PDF 929 KB generado vía Chrome headless + Pillow.
- **Blog post publicado** — https://cobalto-sec.tech/blog/2026-07-04-corvus-mcp-audit-ekoparty — stats actualizados, findings CS11–CS15, FP cal v3, ref al CFP. Slides en producción: `/static/slides/corvus-ekoparty-2026.html`.

## [RT-CORVUS-CS15-PING] — 2026-07-06 — CS15 ecosystem scan + 2 GHSAs · 300 servers milestone

- **CS15 + CS15B — PyPI zero-DL docs/academic tier** — 35 targets (25 CS15 + 10 CS15B). 12 OK / 23 ERROR (34% success). 155 raw findings, ~30 TPs. **300 servers total / 4,002 raw / ~1,298 TPs**.
- **CS15-F01 — v1.28.1 docs template cluster (MCP05 XSS ×6)** — Six PyPI packages from completely different domains (AdonisJS docs, Textual TUI docs, byebye-docs, Web3 docs, EEG/PubMed research, SQLite browser) all share the same v1.28.1 codebase/template: `<script>alert(1)</script>` payloads reflected verbatim in error messages. Same template reuse pattern as CS08 arxiv cluster. GHSA-c7g2-vrm2-mrr4. Maintainers: pimentelleo ✅, pon-tanuki ✅, stevefordev ✅.
- **CS15-F02 — bachai-data-analysis-mcp (MCP05 XSS ×4)** — BACH Studio AI Tools (Chinese data analysis server): `load_data`, `describe_data`, `analyze_column`, `correlation_analysis` all reflect `<script>alert(1)</script>` in Chinese error messages (`错误: 不支持的文件类型 - <script>alert(1)</script>`). Score 92/100. GHSA-hg5p-5fpm-rxc5. KiisMyGun ✅.
- **2 GHSAs opened** — GHSA-c7g2 (v1.28.1 cluster XSS) + GHSA-hg5p (bachai XSS). **44 GHSAs total (3 published, 41 draft)**. 4/4 maintainers invited via PATCH `collaborating_users` (PUT `/collaborators` endpoint deprecated by GitHub).
- **DISCLOSURE-PING deferred** — 4 GHSAs without response (GHSA-mf64/7763/pr6r/7w27, deadline 2026-07-09): no REST API for advisory comments → manual action in GitHub web.

## [RT-CORVUS-CS12-SCALE] — 2026-07-06 — CS12/CS13/CS14 ecosystem scans + 8 GHSAs · 288 servers

- **CS12 — npm/PyPI batch scan** — 34 targets (discover.py: npm rounds 5-6 + PyPI curated). 16 OK / 18 ERROR (47% success). 336 raw findings, 7 TPs curated. Key findings: pincushion-mcp MCP09 prompt injection ×14 params, campertunity SSRF → 169.254.169.254, live-translate-mcp write-path traversal, @oraclaw/mcp-server hidden `_debug` param (MCP01), langsmith-mcp-server debug escalation (EXT11), @uploadkitdev/mcp response flooding (MCP06). **250 servers total / 3,311 raw**.
- **CS13 — npm round 7 + PyPI curated expansion** — 32 targets (heavily SaaS-auth: Transcend×7, Qingflow×2, Xero, PowerBI, Gmail-OAuth). 6 OK / 26 ERROR (81% error — auth-required saturation). 60 raw findings, 2 TPs. EXT11 debug escalation (gezhe-mcp-server); mcp-server-fetch SSRF/injection by-design. **256 servers total / 3,371 raw**.
- **CS14 — PyPI non-zero downloads + arxiv cluster + docs servers** — 68 targets (zh-file/filevine/vipmp-docs/shadcn-docs/arxiv cluster ×10 + file/database tier). 32 OK / 36 ERROR (47% success). 476 raw findings, 10 TPs curated. **288 servers total / 3,847 raw / ~1,268 TPs**.
- **CS14-F01 — SSRF + prompt injection (vipmp-docs-mcp)** — SoftwareOne Adobe VIPM documentation server: `search_vipmp_docs.query` makes outbound HTTP to attacker-controlled hosts (SSRF, MCP05) + `review_request_body`/`debug_error_code` reflect injected instructions (MCP09 ×2). Unexpected HTTP calls for a documentation search tool. GHSA-grw7-4f4v-ffq9.
- **CS14-F02 — Path traversal + shadow tools (fastmcp-file-server)** — `write_file.write-path` has no scope restriction (MCP07, arbitrary filesystem write). Tools named `read_file`/`write_file`/`create_file`/`delete_file` shadow built-in names (MCP03). GHSA-v2cj-6hxv-53r2.
- **CS14 — arxiv cluster pattern** — 9/10 arxiv package variants successful; all exhibit same XSS reflection from CS08 (upstream template reuse across PyPI namespace squatters).
- **6 CS12 GHSAs opened** — GHSA-9c4v (pincushion MCP09), GHSA-jgxf (campertunity SSRF), GHSA-554r (live-translate path traversal), GHSA-5f2h (oraclaw hidden param MCP01), GHSA-2h69 (langsmith EXT11), GHSA-3jc8 (uploadkitdev MCP06). 5/6 maintainers invited (campertunity: GitHub org, no personal user).
- **2 CS14 GHSAs opened** — GHSA-grw7 (vipmp-docs SSRF+injection, smeeks-swo ✅), GHSA-v2cj (fastmcp-file-server path traversal + shadow tools, Luxshan2000 ✅). **42 GHSAs total (3 published, 39 draft)**.
- **discover.py dedup fix** — npm path now checks `scope_part` (e.g. `browserbasehq`) against existing history — prevents scoped packages like `@browserbasehq/mcp` re-appearing after their scope is in history DB.
- **PyPI discovery** — 233 new candidates identified from PyPI Simple index + Libraries.io. Non-zero DL tier (top 35 by downloads) used for CS14; zero-DL academic/docs tier available for CS15.

## [RT-CORVUS-CS11] — 2026-07-06 — CS11 awesome-mcp-servers scan + FP calibration v3 + 5 GHSAs

- **CS11 — awesome-mcp-servers ecosystem scan** — 58 targets from 4 curated lists (punkpeye/appcypher/wong2/modelcontextprotocol) with GitHub link resolution. 39 OK / 19 ERROR (67% success — best rate since CS02). ~490 raw findings, 16 TPs curated (F01–F16) across 11 servers. Dataset: **234 servers total / ~2,975 raw / ~1,249 TPs**.
- **CS11-F01/F12/F09 — EXT12 prompt template injection cluster** — Three independent servers (android-mcp-server, @mymedi-ai/mcp-server healthcare, emilia-protocol payments) with `prompts/get` reflecting `CORVUS_INJECTION_TEST_{{7*7}}` verbatim in LLM message templates. Healthcare context (DMEPOS billing, claim scrubbing, denial analysis) and payment/trust gate context elevate impact.
- **CS11-F01 — MCP08 anti-forensics (android-mcp-server)** — `clear_logs` tool destroys Android audit trail. Combine with `tap_sequence` (arbitrary UI automation) for exfiltrate-then-cover chain. Same pattern as CS06 godot-mcp `clear_console_log`.
- **CS11-F04 — XSS cluster ×6 (@tensorfeed/mcp-server)** — `is_service_down`, `failover_verdict`, `pricing_series`, `status_uptime`, `benchmark_series` all reflect `<script>alert(1)</script>` verbatim. AI service monitoring MCP with direct output injection into LLM failover reasoning.
- **CS11-F10 — SQLi pattern (a2asearch-mcp)** — `' OR '1'='1` reflected in `search_agents` and `list_agents` error context — consistent with raw SQL query construction.
- **5 GHSAs opened** — GHSA-6f4g (@mymedi-ai healthcare EXT12), GHSA-wx78 (@tensorfeed XSS×6), GHSA-xh32 (android MCP08+MCP02), GHSA-32vx (emilia-protocol payments EXT12), GHSA-2mq4 (a2asearch SQLi+XSS). 4/5 maintainers invited (emilia-protocol: no public repo). Publish deadline: 2026-08-06.
- **FP calibration v3** — `token_exposure.py`: (1) `_is_type_annotation_match` now strips trailing JSON punctuation (`",}])`) before regex match — fixes crypto ticker FP (`"token": "BTC,"` → `BTC` correctly suppressed). (2) New `_is_missing_credential_context()` function detects "not set"/"not configured"/"env var" error messages — eliminates ~44 CRITICAL FP from mcp-discord-bridge. **18 new tests (744 total)**.
- **CS11 FP analysis** — mcp-discord-bridge (44 CRITICAL, all FP): Discord bot token not configured → every tool call returns error with "TOKEN" keyword → `token_exposure` fires. x402 (3 CRITICAL, all FP): `"token": "BTC"` is a cryptocurrency ticker field, not a credential. Both patterns now calibrated.

## [RT-CORVUS-REPO-AUDIT] — 2026-07-06 — Repo cleanup + docs sync (195 servers / 29 GHSAs)

- **Privacy fix** — Removed `case-studies/DISCLOSURE-BATCH2-PROMPT.md` (session context doc accidentally committed to public repo). Added `.gitignore` pattern `case-studies/*-PROMPT.md` to prevent recurrence.
- **CFP + technical paper sync** — `cfp-ekoparty-2026.md` + `technical-paper-ekoparty-2026.md`: updated all stats to CS10 baseline (101→195 servers, 1.267→2.485 raw, 741→1.220 TPs, 24→29 GHSAs, 4→10 case studies). Technical paper dataset table extended with CS05-CS10 rows. Version header v1.0.1→v1.3.1.
- **update-public.py fix** — Case study count now derived dynamically from `public-stats.yaml` keys (was hardcoded "three"). Disclosure section uses real case study count (was using `len(published_list)`). README research table simplified to aggregate format.
- **README sync** — Re-run update-public.py: "three case studies" → "ten case studies", disclosure: "3" → "10 case studies".
- **CobaltoSec-Web portada sync** — `StatsStrip.tsx`: 101→195, 741→1220 TPs, 24→29 advisories. `Hero.tsx`: "24 advisories, 101 servers" → "29 advisories, 195 servers".

## [RT-CORVUS-CS10-NPM] — 2026-07-06 — CS10 npm (maybe-auth) scan — browser SSRF + CircleCI CRITICAL

- **CS10 — npm maybe-auth ecosystem scan** — 50 targets (auto-discovered via Round 4 queries + 5 manual high-value). 17 OK / 33 ERROR (34% success). 245 raw findings / ~75 TPs (~69% FP). Dataset: **195 servers total / 2,485 raw / 1,220 TPs**.
- **discover.py Round 4** — +8 npm queries (vscode/cline/zed mcp, mcp-wrapper/bridge/code-server, mcp-search-server, langchain mcp). +2s inter-query delay fix for npm 429 rate limiting. `--include-maybe-auth` flag to capture auth-gated servers at >25 dl/wk threshold.
- **CS10-F01 — CircleCI CRITICAL (MCP03)** — `@circleci/mcp-server-circleci` (30k dl/wk): `create_prompt_template` tool description embeds multi-paragraph LLM instructions ("ABOUT THIS TOOL:" heading with numbered steps). First CRITICAL tool-poisoning finding in a CI/CD provider's official MCP server.
- **CS10-F02 — Browser SSRF sistémico (EXT04)** — Two independent browser MCP servers both navigate to `169.254.169.254` (AWS metadata endpoint) without RFC-1918 blocking: `@agent-infra/mcp-server-browser` (16.5s timeout) + `@browserbasehq/mcp` (12.0s timeout). Cloud IAM credential theft vector. 2 GHSA candidates.
- **CS10-F03 — Arbitrary JS execution** — `@agent-infra/mcp-server-browser`: `browser_evaluate` exposes full `page.evaluate()`. Attack chain: `browser_navigate(attacker-page)` → `browser_evaluate("document.cookie")` → exfiltrate.
- **CS10-F04/F05 — Android MCP ADB shell + SSRF** — `@midscene/android-mcp`: `RunAdbShell` + `act` shadow-tools expose arbitrary ADB shell on connected device. `Scroll` tool params (deviceId/aiActContext) trigger SSRF timeout.
- **CS10-F06 — Credential field in schema (MCP02)** — `@missionsquad/mcp-msq`: `msq_add_provider.apiKey` in inputSchema — prompt injection could instruct agent to transmit API keys via MCP tool call.
- **CS10-F07 — Protocol crash 100%** — 17/17 OK targets crash on batch array, oversized method, or nested params (EXT01/EXT14). Third consecutive CS with 100% crash prevalence.

## [RT-CORVUS-CS09-SMITHERY] — 2026-07-05 — CS09 Smithery scan + discover.py HTTP probe fix · v1.3.1

- **CS09 — Smithery Ecosystem Scan** — First scan of Smithery cloud-hosted HTTP servers. 30 targets (29 HTTP + 1 stdio). 1 OK (arxiv), 29 ERROR (require Smithery API key). 13 raw findings / 9 TPs from arxiv. Dataset: 178 servers total, 2,240 raw findings, 1,145 TPs.
- **Key discovery: Smithery `security:null` ≠ publicly accessible** — Most Smithery cloud-hosted servers require a Bearer token (Smithery API key) at the root URL (`/`). The registry API `security: null` field only indicates Smithery doesn't inject OAuth tokens — not that the server is public. Only official partner servers (arxiv) expose `/mcp` without auth. Future scans need Smithery API key for full ecosystem coverage.
- **discover.py fix: Smithery HTTP connectivity probe** — `check_smithery_entry()` now sends a real MCP `initialize` POST to `deploymentUrl/mcp` and verifies 200 + `result` in response before including the server in candidates. Prevents 29-target all-404 batch runs.
- **discover.py fix: Smithery qname dedup** — `smithery_search()` now deduplicates by `qualifiedName` across pages, preventing duplicate entries in discovery output.
- **discover.py fix: `smithery_to_pkg_obj` preserves `version`** — Pass-through `entry.get("version", "")` instead of hardcoding `""`.
- **3 new E2E tests** — `tests/e2e/test_e2e_smithery.py`: `test_smithery_arxiv_http_scan` (HTTP transport enumeration), `test_smithery_arxiv_http_report_structure` (report schema), `test_smithery_discover_produces_candidates` (subprocess smoke test for discover pipeline).
- **726 tests pass** (2 discover tests updated to use unique mock QNames for dedup correctness).
- **v1.3.1** — `pyproject.toml` bump.

## [RT-CORVUS-CS08-DISCLOSURE] — 2026-07-05 — CS08 GHSAs + engine union-type bugfix

- **3 GHSAs abiertos (CS08)** — todos verificados con re-scan antes de abrir:
  - GHSA-9jp6-hph9-jm5f — `mcp-msaccess-database` HIGH: prompt injection en `access-workflow` (db_path reflejado sin sanitizar) + VBA Shell() como vector RCE. PoC confirmado: payload inyectado verbatim en contexto del agente. Maintainer `unmateria` invitado.
  - GHSA-h6xq-7fpp-q2hf — `arxiv-latex-mcp` HIGH: XSS reflection en 4 tools (original scan reportó 3, re-scan confirmó `get_paper_section` también afectado) + log level escalation sin auth. Maintainer `takashiishida` invitado.
  - GHSA-prc4-649r-564g — `localparse-mcp` HIGH: SSRF confirmado × 2 señales independientes (timeout en `parse_url.url` + timing en `parse_url.result_type`). Sin repo GitHub público — GHSA sin collaborator.
- **FP descartado** — `meta-ads-mcp-local` SSRF (CS08-F06): re-scan devolvió 0 findings; timing del scan original era variabilidad de red. Marcado como FP en curated findings.
- **Bugfix engine.py** — `PayloadEngine.build_args()`: `schema.get("type")` puede devolver `["string", "null"]` (union type JSON Schema). Lista no es hashable → `TypeError` en `benign_default()`. Fix: extraer primer tipo no-null antes de lookup. 726 tests pass.
- **Curación CS08 corregida** — XSS count 3→4 tools, CS08-F07 (localparse SSRF) documentado, CS08-F06 marcado FP.

## [RT-CORVUS-SCALE-C] — 2026-07-05 — Scan history DB + discovery fixes · v1.3.0

- **SCALE-C: SQLite scan history** — `corvus/history.py`: módulo con `record_scan()`, `is_recently_scanned()`, `get_scanned_packages()`, `list_scans()`, `aggregate_stats()`. DB en `~/.corvus/history.db` (override: `CORVUS_HISTORY_DB`). Auto-recording en `batch.py` vía `_record_to_history()` (hook post-scan por target, nunca propaga errores al batch). `run_batch()` acepta `case_study: str | None` para tagging. `discover.py` carga `get_scanned_packages()` al inicio y los agrega a `existing` — evita re-descubrir targets ya escaneados.
- **`corvus history` CLI** — nuevo subcomando: tabla paginada con ID/fecha/paquete/status/raw-count/case-study/versión. Flags: `--limit N`, `--cs TIER`, `--pkg substr`, `--stats` (resumen agregado + breakdown de error categories). `STATUS_STYLE` coloring: ok=green, error=red, skip=yellow.
- **Discover fix: GitHub npm sin filtro "mcp"** — `github_repo_to_npm_pkg()`: removido `"mcp" not in name` — repos `topic:mcp-server` son MCP servers por definición, el nombre del paquete npm no necesita contener "mcp". Antes: 2/210 candidatos. Después: 15/210.
- **Discover nuevo: GitHub uvx packages** — `github_repo_to_uvx_pkg()`: extrae nombre PyPI via `pyproject.toml` (`name = "..."`) para repos Python sin `package.json`. `check_github_repo` intenta npm → uvx en cascada. `build_target_entry` genera `["uvx", pkg]` cuando `_transport == "uvx"`.
- **Discover: `--output-file` flag** — stem del archivo de salida separado de la fecha. Permite `--output-file candidates-cs07-github-2026-07-05` para no sobreescribir la corrida PyPI del mismo día.
- **Discover: dedup desde scan history** — `run()` importa `get_scanned_packages()` de `corvus.history` y agrega el set a `existing`. Discovery automáticamente skipea targets ya escaneados en corridas anteriores.
- **+9 tests** — `tests/test_history.py`: record/retrieve, is_recently_scanned × 3, get_scanned_packages, aggregate_stats, list_scans filter × 2, no_db_returns_empty. **726 tests pass**.
- **v1.3.0** — `pyproject.toml` bump.

## [RT-CORVUS-SCALE-B] — 2026-07-05 — Module parallelism + error categorization + discovery expansion · v1.2.0

- **S0 — Error categorization** — `_classify_startup_error(e)` en `batch.py`: parsea stderr de `ServerStartupError` → categorías `credentials / browser / runtime / network / unknown`. `BatchResult.add()` acepta `error_category`; `summary_md()` muestra `ERROR (credentials)` etc. en la tabla. Dato para paper: 54% startup ERROR en npm, ~40% = credenciales externas.
- **S1 — Module parallelism intra-scan** — `StdioTransport` ahora tiene reader multiplexado: `_reader_loop()` corre como background task, enruta respuestas por `req_id` a `asyncio.Future` individuales vía `_pending: dict[int, Future]`. `send_request()` usa `_write_lock: asyncio.Lock` para serializar escrituras y `wait_for(fut, timeout)` en vez de `readline()`. `pause_reader()` / `resume_reader()`. En `_scan_one()`: 4 grupos — (1) ~28 módulos independientes vía `asyncio.gather` (reader activo), (2) `batch_dos`/`proto_fuzz`/`sampling_probe`/`elicitation_probe` secuenciales con reader PAUSADO (leen stdout directo), (3) `rug_pull` con reader REANUDADO, (4) `cancellation_probe` con reader PAUSADO (crashea el server). Fix crítico: sin el grupo 2, estos módulos compiten por stdout con el reader loop → hang de 600s. Speedup real: 13s vs 600s en suite de tests. 3-5x en producción.
- **S2 — Smithery + GitHub en discover.py** — `smithery_search()` pagina `registry.smithery.ai/servers` (handles `servers`/`results`/`items` key), `smithery_to_pkg_obj()` normaliza a formato npm. `github_mcp_search()` busca `topic:mcp-server` con GitHub API + soporte `GITHUB_TOKEN`, `github_repo_to_npm_pkg()` resuelve npm name via `package.json`. `--source` acepta `smithery | github | all`.
- **S3 — PyPI auto-discovery** — `pypi_search_by_name()` fetcha PyPI Simple index (`pypi.org/simple/`), filtra nombres con "mcp", cae a `PYPI_CURATED` si result count ≤ curado. `pypi_search_librariesio()` usa Libraries.io API (`LIBRARIES_IO_API_KEY`), pagina, cae a `PYPI_CURATED` en error. Reemplaza lista hardcodeada de 25 entries.
- **+28 tests nuevos** — `tests/test_transport.py`: concurrent routing (5 paralelos, echo A→A/B→B/C→C, pause/resume reader). `tests/test_batch.py`: classify error × 5 categorías, `error_category` en summary, parallel scan completes. `tests/test_discover.py`: Smithery pagination/error/normalize, GitHub pagination/pkg-json, PyPI filter/fallback, librariesio pagination. **717 tests pass**.
- **v1.2.0** — `pyproject.toml` bump. Publish PyPI pendiente (manual).

## [RT-CORVUS-SCALE-A] — 2026-07-05 — Batch UX: inline targets + concurrency + Rich progress

- **S2 — Inline targets sin YAML** — `corvus batch --stdio "npx foo" --stdio "npx bar" --http "http://localhost:3000/mcp"`. YAML sigue soportado; ambos son mutuamente excluyentes. Helpers `_name_from_cmd` (strip `npx`/`uvx`/`python -m` → nombre corto) y `_name_from_url` (host:port). Deduplicación automática de nombres (`foo`, `foo-2`).
- **S3 — `--concurrency N` / `-j N`** — reemplaza el `_BATCH_CONCURRENCY = 5` hardcodeado en `batch.py`. El semáforo async ahora toma el valor del flag; `run_batch()` expone `concurrency: int = 5`.
- **S4 — Rich live progress panel** — `_run_batch_with_progress()` activo en TTY; non-TTY cae al modo plano. Columnas: spinner, nombre del target, status (`·  queued` → `scanning…` → `✓  2C 1H (72/100)` / `✗  error`), elapsed. Callback `on_status(name, status, detail)` en `_scan_one` y `run_batch` (opcionalmente inyectable desde tests). Panel con `transient=True` → limpia al terminar y muestra tabla summary final.
- **+18 tests** — `tests/test_batch_ux.py`: `_name_from_cmd`, `_name_from_url`, `_build_inline_targets` (incluyendo dedup y mixed), `concurrency` param, `on_status` callbacks (start/done/skipped). **689 tests pass**.

## [RT-CORVUS-CS05] — 2026-07-05 — CS05 scan + FP calibration v2

- **CS05 scan completo** — 30 targets (20 CS05-A + 10 CS05-B). 12 servers OK / 16 startup ERROR (57%) / 2 skipped (browser automation). ~105 raw findings → ~50 TP / ~55 FP. Alta tasa ERROR: mayoría requieren contexto externo (TouchDesigner, Storybook, Terraform, ioBroker). Security tools mcpwall/mcp-guard crashearon sin config — blind spot en la cadena de auditoría.
- **8 hallazgos curados** (`case-studies/cs05-mcp-ecosystem/findings-curated-cs05.md`): F01 LLM instruction injection via description (next-devtools HIGH, OWASP MCP03), F02 bidirectional tool chaining (next-devtools MED, EXT06), F03 input reflection en error msg (next-devtools MED, MCP05), F04 shadow tool exec Python+node (touchdesigner HIGH, EXT03), F05 prompt injection via `prompts/get` (touchdesigner HIGH, MCP10), F06 protocol crash cascade (5 servers HIGH, EXT01), F07 scope creep read→write label (motiff MED, MCP02), F08 missing required fields validation (siemens + mastra MED, EXT01). No nuevos GHSAs.
- **4 FP fixes (calibración v2)** — `token_exposure.py`: `_is_connection_error_text()` — skip IP match cuando el texto es help de conexión fallida (elimina 12 LOWs FP por server tipo touchdesigner). `injection.yaml`: `"null"` y `"undefined"` eliminados de `generic_string` — FP sistémico en cualquier JSON con campos nulos. `shadow_tool.py`: `_TRANSPARENT_EXEC_NAME_RE` — prefijos `execute_/exec_` → MEDIUM 65% (nombre auto-documenta la capacidad, no ocultación adversarial). `batch.py`: `status: done/error` también skipean targets, además de `skip`.
- **public-stats.yaml actualizado** — cs05 block + totals: 113 servers / 1372 raw findings / 791 TP.

## [RT-CORVUS-SCALE-S1] — 2026-07-05 — Auto-discovery npm + CS05 targets curados (30)

- **`scripts/discover.py`** — script interno de auto-discovery: 8 queries npm, cross-ref contra CS01–CS04 (461 packages conocidos), filtra por downloads (>25/wk) + heurística auth (likely-noauth / maybe-auth / likely-auth), genera candidates YAML en tracking format estándar. Round 1: 1075 pkgs nuevos. Round 2 (threshold 25, queries adicionales claude/cursor): 1332 pkgs, 50 candidatos finales.
- **CS05-A** — 20 targets curados (`case-studies/cs05-mcp-ecosystem/targets-cs05-a.yaml`): chrome-devtools (2.1M/wk), storybook (1.7M/wk), pandacss (254k), agentation, next-devtools, mcp-hello-world, mcp-searxng, mcp-server-airbnb, terraform, newsnow, openapi-mcp-generator, goke, axe, mcp-server-sqlite-npx, docs, browsermcp, coinbase-cds, motiff, theia-ai, touchdesigner.
- **CS05-B** — 10 targets adicionales del round 2 (`case-studies/cs05-mcp-ecosystem/targets-cs05-b.yaml`): mui (4k/wk), excalidraw (3.6k/wk), siemens-ix-react (1.7k/wk), mcpwall (security proxy), mcp-guard (security middleware), mastra-mcp-registry (meta-registry), handoff (AI memory), bunli-plugin, vibelens, iobroker.
- Total CS05: **30 targets pendientes de scan** — `corvus batch targets-cs05-a.yaml && corvus batch targets-cs05-b.yaml`.

## [RT-CORVUS-CLI-FP] — 2026-07-05 — CLI UX + FP calibration · v1.1.0

- **CLI aesthetics** — banner TTY-aware (supprimido en pipe/SARIF), argumento posicional `target` con auto-detect transport (`http://` → HTTP, else stdio), `--fast/-F` (static only), output nmap-style (dim para módulos limpios, badge `(N)` para findings), timing al final. `_NoiseFilter` elimina asyncio Windows pipe noise en stderr.
- **cmd-injection FP** — `echo` tool ya no dispara HIGH: `_TRANSFORMATION_TOOL_RE` extendido con `echo|mirror|reflect|passthrough|repeat|ping`. `echo.message` HIGH (85%) → LOW (30%).
- **response-flood FP** — `_SLOW_BY_DESIGN_RE` nuevo: herramientas con `long[._-]?running|slow|delay|sleep|wait_for|background|deferred` en el nombre saltan el check de tiempo. `trigger-long-running-operation` MEDIUM eliminado. `get-env` oversized (CS01-F38 TP) surfaceó correctamente.
- **rug-pull FP** — `_PROBE_ARTIFACT_URI_RE` nuevo: URIs que contienen traversal encoding (`../`, `%2e%2e`, `%252e`, `(?<![:/])//`), Unicode fullwidth dot-dot (`．．`), Windows drive+backslash (`C:\`), buffer fills, `%SYSTEM` → severidad LOW 40% "probe input persisted". 22 CRITICAL FP → 4 (reducción 82%). 671 unit tests pass.
- **v1.1.0** — `pyproject.toml` bump. `dist/cobaltosec_corvus-1.1.0.*` listo; PyPI publish pendiente (manual).

## [RT-CORVUS-CFP-EKO] — 2026-07-04 — CFP Ekoparty 2026 · draft completo

- **CFP listo para submitear** — `case-studies/cfp-ekoparty-2026.md`: descripción en español (8 hallazgos principales), outline 30 min, bio del speaker. Título: *"Corvus: Seguridad en el Ecosistema MCP a Escala"*. Deadline Sessionize: 2026-08-14.
- **Paper técnico adjunto** — `case-studies/technical-paper-ekoparty-2026.md`: 8 secciones cubriendo EXT14 crash universal, EXT08 sampling C2 encubierto, rug pull mid-session, vigilancia AI, SSRF con timing evidence, supply chain cascade, evolución FP rate 42%→7%, 24 GHSAs.
- **Slide deck** — 18 slides, dark amber theme, navegación teclado/swipe, self-contained HTML. `Downloads/slides-ekoparty-2026.html`.

## [RT-CORVUS-CS04-CURATION] — 2026-07-03/04 — Curación completa CS04 · FP rate ~44% · 3 GHSAs

- **Curación completa CS04** — 979 raw findings (47 servidores) clasificados manualmente. 47 IDs asignados (CS04-F01–F47). FP rate global ~44%: CRITICAL 86.8% FP (195 sveltejs lazy-load + 3 otros), HIGH ~61% FP (strptime 33 + API echo 62+ + dict 10), M/L/I ~26% FP (protocol TPs dominan). Sin sveltejs outlier: **~30%** — comparable a CS01 (23.1%) y CS02 (20.3%).
- **Nuevos patrones FP documentados** — 4 patrones nuevos no vistos en CS01-CS03: docs server lazy-loading (MCP06, 195 FP de sveltejs), Python strptime error reflection (MCP05, 33 FP de lunar), API error echo third-party (MCP05, 62+ FP en 11 servers), env var NAME en error message (MCP01, FP-downgrade a INFO).
- **Nuevos patrones TP para CFP** — 4 patrones únicos CS04 confirmados: SaaS description mutation rug-pull (F08, ×29 tools, billing logic), prompt arg interpolation en `prompts/get` (F11, ×5 prompts), covert AI agent surveillance tool (F30, clarvia), SSRF outbound arbitrario via `scrape.url` (F41, confirmado 2026-07-04). F32 (arxiv stored SQL) descartado como FP — query parametrizado verificado.
- **3 GHSAs CS04 creados** — GHSA-2g9w-p2x3-97pp (`mcp-devutils` CRITICAL: RSA key + description mutation) · GHSA-w5c8-hjv7-p95r (`@aryanbv/pdf-toolkit-mcp` MEDIUM: prompt injection) · GHSA-78qj-r76x-2jvh (`@pulsemcp/pulse-fetch` HIGH: SSRF CWE-918, verificado con capture server). Portfolio: **24 GHSAs** (3 published, 21 draft).
- **Verificación post-curación** — F32 (arxiv stored SQL): FP — `check_alerts(topic=inexistente)` → `checked_topics:0` confirma WHERE parametrizado. F41 (pulsemcp SSRF): TP — `scrape(url=http://127.0.0.1:PORT/)` → request recibido, response `SSRF_CAPTURED`.
- **public-stats.yaml actualizado** — CS04: TP ~550, FP ~429, FP rate 44.0. 24 GHSAs. README + CobaltoSec-Web sincronizados.

## [RT-CORVUS-CS04] — 2026-07-03 — Dataset expansion 57→101 unique servers

- **101 MCP servers auditados** — CS04 añade 44 servers únicos nuevos (47 OK, 3 dups de CS01/CS02) via batches D/E/F/G/H/I. Categorías: UI frameworks (Svelte, Flowbite, DaisyUI, Chakra, Taiga, Mantine, ShadCN CLI, Synergy, SAP UI5), news APIs (HN×3, PulseMCP×2), academia (arxiv, pubmed, academic-mcp, Open Library), crypto (CoinGecko), dev-utils (mcp-devutils, devutils-mcp-server, npm-registry, npm-helper), weather (open-meteo×2, dangahagan), finanzas (TradingView, MarketNow, Frankfurter), datos (DuckDB, Excel, pdf-toolkit, mathtools), misc (mcp-web-search, eslint, wiki×2, clarvia, rosetta, cyanheads-git, hero-fe, faker).
- **979 raw findings** (228C / 101H / 191M / 326L / 90I) — top: sveltejs-mcp (209, 195C), mcp-devutils (168, 30C), lunar-mcp-server (78, 33H). Curación pendiente en RT-CORVUS-CS04-CURATION.
- **CS04-STATUS.md** — tabla completa 47 servers ranked por findings, guía de curación, patrones FP conocidos como filtro rápido para el bloque siguiente.
- **public-stats.yaml corregido** — `totals.servers=101`, `totals.raw_findings=1267` (288 CS01-03 + 979 CS04 confirmado). CobaltoSec-Web actualizado: 101 servers / ~1388 findings.

## [RT-CORVUS-PUBLIC-AUDIT] — 2026-07-03 — Audit público + infraestructura sync docs

- **Audit GHSAs completo** — 21 Corvus GHSAs verificados contra GitHub API. Encontrado: GHSA-pr6r severity MEDIUM→HIGH en DISCLOSURE-PROCESS.md (token exposure es HIGH, confirmado por API). SIGUIENTE.md tenía count 17 (vs 21 real) y 4 CS03 GHSAs listados como "pendientes" cuando ya estaban abiertos — ambos corregidos.
- **README actualizado** — v0.9.1→v1.0.1, 18→34 módulos (tabla completa con los 16 nuevos de V27-V30), research stats CS01+CS02+CS03 (~191 TP / 57 servers), disclosure table 3 published + 18 coordinated (removido "MSRC pending" incorrecto), CLI commands `corvus init/report/diff/score` + flags `--delay/--env/--score`.
- **CobaltoSec-Web actualizado** — `projectsData.ts`: stats 57 servers / 21 GHSAs, removido "MSRC pending". `toolsData.ts`: tagline "21 advisories" reemplaza "4 CVEs".
- **Infraestructura sync** — `case-studies/public-stats.yaml` como fuente única de verdad (versión, módulos, stats CS01/02/03, GHSAs published). `scripts/update-public.py` lee YAML + GitHub API → parchea README y web entre comment markers `<!-- CORVUS_xxx_START/END -->`.
- **Cierre skill actualizado** — P5b (sync docs públicos, corre update-public.py) + P5c (repos públicos, incluye CobaltoSec-Web). CobaltoSec CLAUDE.md: nuevo bloque "Repo CobaltoSec-Web" en la sección de repos públicos.

## [RT-CORVUS-CAL-CS03] — 2026-07-03 — Calibración FP post-CS03 + curación dataset

- **cancellation_probe cascade FP eliminado** — EXT14 HIGH se generaba falsamente cuando `proto_fuzz` mataba el server en módulos anteriores (34/34). Agregado health-check `_server_alive()` al inicio de `run()`: si el server no responde antes del probe, retorna `[]`. Los GHSAs EXT14 (notion/mysql/nx-mcp) vienen de delta scans sin proto_fuzz — todos TP. 16 tests cancellation_probe.
- **SQL FP calibration v6 (CS03 aws-docs)** — `"SQL Server"` y `"ORA-"` eliminados de `_SQL_ERROR_SIGNATURES`: aparecen en contenido de documentación AWS y generaban CRITICAL falsos. Reemplazados por patrones específicos (`ORA-00`, `Msg 102,`, `Unclosed quotation mark`). Además: skip de `_sql_error_confirmed` para parámetros en `_ECHO_FIELD_NAMES` (search tools retornan docs con contenido arbitrario). 3 tests nuevos en `test_fp_calibration_v5.py` — **671 unit tests pass**.
- **CS03 dataset expansion curado** — 8 targets nuevos (~116 raw findings). Curación: 39 TP / 3 FP. Highlights: SAP SSRF+injection (GHSA-vrmg), markitdown SSRF 12s timeout (GHSA-frqj, LFI descartado — playwright-mcp artifact), context7 injection reflection (GHSA-8ggf), heroku credential scope creep (GHSA-4r48). 4 GHSAs CS03 abiertos (publish 2026-10-03). Portfolio: **21 GHSAs** (3 published, 18 draft).
- **Cleanup scan artifacts** — `.playwright-mcp/` + archivos con nombres de payloads path traversal URL-encoded (`%252e*`, `..%5c*`) borrados y agregados a `.gitignore`.

## [RT-CORVUS-CS02-DELTA] — 2026-07-03 — Delta scan 7 módulos + 6 GHSAs + quality pass

- **Delta scan ejecutado** — 7 módulos faltantes (EXT08-EXT14: completion/logging/prompts-injection/cursor/cancellation + github-advisory/npm-behavior) contra CS01 (20 targets) + CS02 (49 targets). Resultados en `scan-delta-v102/`.
- **EXT13 cursor_probe → FP sistémico** — 80%+ hit rate era la señal: non-paginators que ignoran el cursor parameter están en spec. Descartado de todos los candidatos de disclosure.
- **Curación delta** — EXT11 (`logging/setLevel` sin auth, conf=85%), EXT12 (prompts/get injection reflejada, conf=88%), EXT14 (crash en `notifications/cancelled` ID desconocido, conf=85%). IDs asignados: CS02-D01 a D12 / CS01-F92.
- **6 nuevos GHSAs creados** — nx-mcp (D01+D02, HIGH), @jpisnice/shadcn-ui-mcp-server (D03-D05, HIGH), european-parliament-mcp-server (D06-D08, HIGH), @get-technology-inc/jamf-docs-mcp-server (D09-D11, HIGH), @notionhq/notion-mcp-server (D12, HIGH), @benborla29/mcp-server-mysql (CS01-F92, MEDIUM). Collaborators invitados 6/6. Portfolio: **17 Corvus GHSAs** (3 published, 14 draft).
- **Calidad disclosure** — 6 descripciones reescritas al estándar playwright/sqlite: PoC numerado con `npx -y <package>` + JSON-RPC exacto, `## Notes` con IDs (CS02-Dxx), `exploitation_confirmed`, "0 prior advisories", link a `github.com/CobaltoSec/corvus`, contexto de ataque en LLM agent context.

## [RT-CORVUS-CS02-RESCAN] — 2026-07-02 — CS02 re-scan v1.0.1 + curación + disclosure

- **Re-scan CS02 completo** — 28/29 targets con 34 módulos v1.0.1 (1 skip-env: mysql-mcp-server). 421 findings brutos (4C 61H 147M 181L 28I).
- **Curación cuarta pasada F52-F69** — 18 nuevos TPs. Stats CS02: ~51 TP / ~13 FP (FP rate ~20.3%). Nuevos clusters: EXT01 batch_dos (codeloop, upg), LFI CRITICAL (myclaw), injection en nationalparks/pubmed/spartan/javadc/malicious/mysql.
- **4 GHSAs operados:**
  - GHSA-qwwj-38wj-ffvw (myclaw-toolkit) → HIGH→**CRITICAL**, agrega LFI via `file://` en `read_page.url` (lee `/etc/passwd` real), CWE-918+CWE-22.
  - GHSA-rqqc-2cx5-vp44 (mcp-server-nationalparks) — 🆕 HIGH, injection `findParks.stateCode`, 13,831/wk.
  - GHSA-m2x9-5c27-vvc3 (@cyanheads/pubmed-mcp-server) — 🆕 HIGH, injection 3 params API, 3,385/wk.
  - GHSA-m6h2-xr6q-9m7p (@idachev/mcp-javadc) — 🆕 HIGH, injection `classFilePath` + `packageName`, CWE-77+CWE-22.
- **Invite collaborators corregido** — endpoint correcto: `PATCH /security-advisories/{ghsa}` con `collaborating_users` (no `PUT /collaborators` que da 404). KyrieTangSheng/cyanheads/idachev/Dusheh invitados. 4/4 ✅.
- **DISCLOSURE-PROCESS.md** — flujo bash completo copy-paste (crear+invitar en un bloque), tabla errores comunes, tabla maintainers actualizada (9 entries), CWE-22 agregado. Portfolio total: **11 GHSAs** (4 published, 7 draft).

## [RT-CORVUS-DISC-01] — 2026-07-02 — Disclosure operations + auditoría advisory portfolio

- **GHSA-43j9-hmpq-cgv7 reclassificado** — remnux-mcp-server: CRITICAL→MEDIUM. Mantenedor (lennyzeltser) confirmó que `run_tool` es by-design. El finding real era HTTP transport sin auth, fixeado en v0.1.53. CWE-78→CWE-306, summary actualizado, publicado.
- **DISCLOSURE-PROCESS.md creado** — playbook completo de disclosure desde Corvus: scripts PowerShell para crear/actualizar/publicar GHSAs via API, tablas CWE/severity mapping, maintainers conocidos, límites de la API (comments no accesibles, notifications no detectan respuestas de advisory).
- **DISCLOSURE-BATCH2-PROMPT.md creado** — mini prompt listo para sesión de disclosure de F86/F87/F89/F90.
- **Auditoría portfolio completo (20 advisories)** — 6 fixes aplicados: duplicado GHSA-mc5c cerrado, CWE-89 en 2 SQL injection (era CWE-95), CWE-306 en auth bypass sin CWE, CWE-522 en token exposure, summary limpiado (removido prefijo "CRITICAL" redundante).
- **Scopes PAT documentados** — `repo` + `notifications` + `write:discussion`. `security_events` incluido como sub-scope de `repo`. Comments en advisories: no existe endpoint REST con ningún scope.

## [RT-CORVUS-CS01-RESCAN] — 2026-07-02 — CS01 re-scan v1.0.1 + GHSAs #7+#8

- **Re-scan CS01 completo** — 20 targets con los 34 módulos de v1.0.1 (incluyendo osv-supply-chain, proto_fuzz v2, rug_pull v2, completion/logging/prompts/cursor/cancellation-probe).
- **+19 findings nuevos (F73-F91)** — 18 hallazgos OSV + 3 proto-crash confirmados. Stats CS01: 91 findings (70 TP / 21 FP, 23.1%).
- **n8n-mcp Score 100/100** — server más vulnerable. 9 GHSAs activos incluyendo CVE-2026-39974 SSRF.
- **FP cluster server-everything** — 22 CRITICAL rug_pull descartados (demo server by design). Curación funciona correctamente.
- **GHSA-hv3x-m9fv-4vhf publicado** — mcp-server-git (F86/F87). JSON-RPC batch array crash + oversized method. CWE-755, HIGH.
- **GHSA-3f55-qgq4-f88c publicado** — server-sequential-thinking (F90). Oversized method crash. CWE-400, MEDIUM.
- **GHSA-7763-c5gf-v5fj actualizado** — mcp-shell-server F89 proto-crash appended. Total: 8 GHSAs (3 published / 5 draft).

## [RT-CORVUS-V29-E2E] — 2026-07-02 — Suite E2E contra servidores MCP reales

- **`tests/e2e/`** — nueva carpeta de tests de integración end-to-end. Marcados `@pytest.mark.e2e`; excluidos del run por defecto (`addopts = "-m 'not e2e'"`).
- **`conftest.py`** — registra el marker `e2e`; define rutas absolutas a kestrel-mcp / llamascope-mcp / uvx; skip helpers por server ausente.
- **`test_e2e_batch.py`** — 8 tests usando `run_batch()` directamente contra servers reales:
  - kestrel-mcp + llamascope-mcp batch (report.json válido por target)
  - summary.md con columna Score (N/100)
  - combined.sarif con un run por target
  - kestrel tools enumeration (≥1 tool)
  - llamascope tools enumeration (≥1 tool)
  - `mcp-server-sqlite` via uvx (SQL tools detectados)
  - `@modelcontextprotocol/server-everything` via npx (≥5 tools)
  - `skip_existing=True` (report.json no reescrito en segunda run)
- **`pyproject.toml`** — marker `e2e` declarado; `addopts = "-m 'not e2e'"` protege CI.
- **Tests** — 667/667 unit pass + **8/8 E2E pass** (kestrel ✅ llamascope ✅ sqlite ✅ everything ✅).

## [RT-CORVUS-V30] — 2026-07-02 — Risk Score en batch + CVSS v3.1 + combined SARIF

- **Risk Score en batch summary** — `BatchResult.summary_md()` agrega columna `Score (N/100)` usando `compute_risk_score()` por target. `_scan_one()` computa el score y lo propaga a `BatchResult.add(risk_score=...)`.
- **CVSS v3.1 por finding type** — `_CVSS_VECTORS` (23 entradas, una por `OWASPCategory`) en `models.py`. Campo `cvss_vector: str | None` en `Finding` con `model_validator(mode="after")` que auto-popula desde el map si no se setea explícitamente. Override manual soportado. Persiste en JSON.
- **Batch SARIF agregado** — `write_combined_sarif(named_results, output_dir)` en `report.py`: genera `combined.sarif` con un `run[]` por target (SARIF 2.1.0 multi-run). Cada run lleva `automationDetails.id = nombre_target` (de la YAML, no el cmd). Escrito automáticamente en `run_batch()` cuando `sarif=True`. CLI batch imprime path. Apto para GitHub Code Scanning.
- **Tests** — 13 nuevos: `tests/test_cvss.py` (7 nuevos), `test_sarif.py` (+4), `test_batch.py` (+3). Suite: **667/667 pass**.

## [RT-CORVUS-V29] — 2026-07-01 — CLI + Reporting: init/report/score/delay/env/HTML

- **`corvus init`** — genera `corvus.toml` skeleton con todos los campos comentados (transport/cmd/url/modules/timeout/sarif/fail_on/min_confidence/delay/env/headers/plugin_dirs). Falla si el archivo ya existe.
- **`corvus report REPORT.json [--format md|sarif|html|all]`** — regenera reportes desde un `report.json` existente sin re-escanear. Soporta output-dir alternativo con `--output-dir`.
- **HTML report** — nuevo template `report.html.j2` (dark theme, inline CSS): Risk Score con badge colorizado, severity badges por finding, confidence %, payload/evidence en `<pre>`, remediation destacada, footer con versión y módulos. Sin dependencias externas.
- **`--score` en `corvus scan`** — imprime `Risk Score: N/100 — TIER` al final del scan (colorizado: rojo/amarillo/azul/verde por tier). No modifica exit code — es display-only.
- **`--delay N`** — sleep `N` segundos entre módulos para rate limiting / WAF bypass. Configurable también en `corvus.toml` como `delay = 1.5`.
- **`--env KEY=VAL`** — pasa variables de entorno al subprocess MCP stdio (repeatable). Configurable también en `corvus.toml` como `[scan.env]`.
- **Confidence en output de scan** — cada finding en el scan muestra `(N%)` junto a la severidad durante el escaneo en tiempo real.
- **Confidence en `report.md`** — columna `Confidence` agregada a la tabla de cada finding.
- **`ScanConfig`** — nuevos campos `delay: float = 0.0` y `env: dict[str,str]` en `corvus.toml`.
- **`ReportGenerator`** — `write_md()` extraído como método independiente; `write_html()` nuevo; `write()` delega a ambos.
- **Tests** — 25 tests nuevos en `tests/test_cli_v29.py`. Suite: **654/654 pass**.

## [RT-CORVUS-V27+V28] — 2026-07-01 — MCP spec coverage completa + profundidad + supply chain npm

### RT-CORVUS-V27 — 5 nuevos módulos (EXT10-EXT14)
- **`completion-probe`** (dynamic, EXT10) — injection en `completion/complete` argument.value + ref enumeration. HIGH=payload reflejado, MEDIUM=sin validación, INFO=endpoint funcional. stdio + HTTP. 13 tests.
- **`logging-probe`** (dynamic, EXT11) — `logging/setLevel DEBUG` sin auth → HIGH (expone tokens/paths en logs); nivel inválido aceptado → MEDIUM. stdio + HTTP. 12 tests.
- **`prompts-injection`** (dynamic, EXT12) — patrones estáticos en descriptions de prompts (override/persona/confidentiality) + `prompts/get` template injection en arguments (payload reflejado → HIGH) + stack trace en error → MEDIUM. 18 tests.
- **`cursor-probe`** (dynamic, EXT13) — cursor manipulation en `tools/list`: traversal `../../etc/passwd`, overflow 4096 chars, IDOR cursor=0/-1, null cursor. HIGH=crash, MEDIUM=aceptado sin validar. 15 tests.
- **`cancellation-probe`** (dynamic, EXT14) — `notifications/cancelled` race condition: cancel-nonexistent hang/crash (HIGH), flood 10× (HIGH), request/cancel race (HIGH/INFO). stdio-only. 14 tests.
- **OWASPCategory** — EXT10-EXT14 agregados al enum. **Tests: 588/588 pass.** 32 módulos (11 static + 21 dynamic).

### RT-CORVUS-V28 — profundidad módulos + supply chain
- **`rug_pull` v2** — agrega diff de `resources/list` y `prompts/list`: appeared (CRITICAL), disappeared (HIGH), description changed (CRITICAL). Antes solo chequeaba tools.
- **`proto_fuzz` v2** — Probes 6-8: missing `jsonrpc` field (LOW), `id` como array (MEDIUM), `_meta.progressToken` reflection (MEDIUM). Helpers `_send_raw_http` + `_send_raw_stdio` para requests malformados.
- **`response_flood` v2** — timing `time.monotonic()` por tool call (>10s → MEDIUM); detección base64 covert payload via `_check_encoded_payload` (→ MEDIUM).
- **`token_exposure` v2** — `_check_http_headers`: inspecciona headers HTTP response (`Server`, `X-Powered-By`, `X-Debug-Token`, `Set-Cookie` credentials). INFO→HIGH. HTTP-only.
- **`github-advisory`** (static, MCP04) — GitHub Security Advisory REST API por dep de `package.json`; mapea CVSS a severidad CRITICAL/HIGH/MEDIUM/LOW/INFO.
- **`npm-behavior`** (static, MCP04) — npm registry: `postinstall`/`preinstall` con curl/wget/bash/eval → HIGH; postinstall genérico → MEDIUM. Limita a 30 packages.
- **Tests: 629/629 pass.** 34 módulos (13 static + 21 dynamic).

## [RT-CORVUS-V26] — 2026-07-01 — A3+A4+A5: sampling/elicitation probes + oauth_bypass + score + diff CLI

- **M-NEW-01 `sampling-probe`** (dynamic, EXT08, MCP10) — detecta uso malicioso de `sampling/createMessage`: prompt injection (CRITICAL), context exfiltration via `includeContext=allServers` (HIGH), unsolicited sampling (MEDIUM). Re-inicializa declarando `"sampling": {}` en capabilities y usa direct stdin/stdout bypass (igual que `batch-dos`) para capturar mensajes server→client descartados por `send_request`. stdio-only. 28 tests.
- **M-NEW-04 `elicitation-probe`** (dynamic, EXT09, MCP10) — detecta phishing via `elicitation/create`: credential phishing en message (password/token/2FA → CRITICAL), sensitive schema fields (apiKey/password → HIGH), unsolicited elicitation (MEDIUM). 21 tests.
- **M-NEW-02 `oauth-bypass`** (dynamic, MCP07) — detecta auth bypass HTTP: missing auth headers (CRITICAL), invalid Bearer (CRITICAL), URL query credentials (HIGH). HTTP-only. 25 tests.
- **F-04 `corvus score`** — `corvus/scoring.py`: Risk Score 0–100 (`CRITICAL=40/HIGH=15/MEDIUM=5/LOW=1/INFO=0`, weighted by confidence). `risk_tier()` (CLEAR/LOW/MEDIUM/HIGH/CRITICAL). CLI: `corvus score report.json [--json]`. Exportado en `__init__.py`. 22 tests.
- **F-02 `corvus diff`** — `corvus/diff.py`: compara dos SARIF 2.1.0 por `ruleId::message[:120]` key. CLI: `corvus diff old.sarif new.sarif [--json]`. Muestra new/fixed/unchanged. Exportado en `__init__.py`. 22 tests.
- **A3 GitHub Code Scanning** — `.github/workflows/code-scanning.yml`: reusable workflow (`workflow_call` + `workflow_dispatch`) para escanear MCP servers en CI y subir SARIF a GitHub Security tab via `upload-sarif@v3`. Inputs: transport/cmd/url/modules/fail_on/corvus_version. Secret `mcp_header` para servers autenticados.
- **OWASPCategory** — EXT08 (`EXT08_SAMPLING_INJECTION`) + EXT09 (`EXT09_ELICITATION_PHISHING`) agregados al enum.
- **Tests** — 516/516 pass (27 módulos: 11 static + 16 dynamic). +119 tests vs V26 A1+A2.

## [RT-CORVUS-V26] — 2026-07-01 — A1+A2: batch parallelism + 2 nuevos módulos + mejoras

- **BATCH-FIX (3 fixes)** — `batch.py` refactorizado: `asyncio.gather` + `asyncio.Semaphore(N=5)` para scans paralelos (~5× más rápido sobre 54 servers); 4 módulos faltantes sincronizados (`supply-chain-python`, `resource-uri`, `tool-chaining`, `response-injection`); parámetro `skip_existing=True` para resume/skip de targets con `report.json` existente.
- **M-NEW-05 `osv-supply-chain`** (static, MCP04) — query a OSV.dev API (free, sin auth) para vulnerabilidades conocidas. Cubre stdio npm y Python (uvx/uv), y HTTP transport vía `server_name` del initialize. Sin dependencias locales. 16 tests.
- **M-NEW-03 `batch-dos`** (dynamic, EXT01) — envía JSON-RPC batch arrays (no estándar en MCP) directamente al transport para detectar crash/DoS y batch acceptance no intencional. Probe small (5 ×) y large (50 ×). HIGH=crash, MEDIUM=batch accepted. 23 tests.
- **Mejoras módulos** — `init_audit`: versiones futuras (`9999-99-99`, `2030-01-01`) + missing field + type confusion. `ssrf`: Azure IMDS, GCP metadata.google.internal, Alibaba 100.100.100.200, decimal IP 2130706433; signatures Azure/GCP. `proto_fuzz`: nested params 50 niveles + type confusion string params.
- **Tests** — 397/398 pass (1 flaky pre-existente: timing Windows bajo carga).

## [RT-CORVUS-V25] — 2026-07-01 — A1→B1: FP calibration v5 + dataset definitivo

- **A1 — token_exposure dedup** — `seen_signals: set[str]` por tool impide emitir 2 findings idénticos cuando el mismo signal aparece en múltiples response texts (benign + error-provoking + oversized). Bug documentado en CS02 remnux-mcp-server (×12 FP-dups por tool).
- **A2 — FP calibration v5** — `cmd_injection.py`: blanket para path params (`category == "path" and not confirmed` → skip). Elimina clase completa de FPs en doc editors (docx-mcp, file converters). `_TRAVERSAL_MARKERS` extendido con `%2e%2e`, `..%2f`, `..%5c` para cubrir URL-encoded traversal payloads que no matcheaban el check de `_is_traversal_payload`. Regresión guard: traversal confirmado (file content / OS error) sigue emitiéndose en path params.
- **A3 — init_audit stats** — `case-studies/init_audit_stats.py`: script de agregación sobre CS01+CS02. Resultado: **37/52 servers (71.2%) aceptan protocol version downgrade** — input directo para CFP. Cero casos de control chars en serverInfo.
- **B1 — Dataset definitivo** — `case-studies/dataset_b1.md`: overview CS01+CS02 (55 servers, ~90 TPs, ~26.8% FP rate), breakdown por OWASP MCP Top 10, prevalencia por tipo (proto crash 27%, shadow tool 44%, supply chain 27%, injection 29%, SSRF 9%), FP rate evolution v0.8.0→v1.0.1+v5, SDK advisory cascade (8+ servers confirmados), ángulos B2 CFP listos.
- **Tests** — `tests/test_fp_calibration_v5.py`: 8 tests nuevos (3 A1, 5 A2). Suite: **359/359 pass**.

## [RT-CORVUS-V24] — 2026-07-01 — D1+D2+D3: v1.0.1 + findings curados + regresiones

- **v1.0.1 publicado** — PyPI + GitHub release. Único cambio: Windows noise fix del bloque V23
- **CS01 findings curados (F63-F72)** — playwright-mcp: shadow tool `browser_run_code_unsafe`, injection `browser_evaluate.function` + `browser_network_request.filename`, SSRF auto-detectado via timeout, proto-crash. mcp-server-fetch: SSRF timing bypass confirmado (private-ip bypass). mcp-server-fetch + mcp-server-time: init_audit sistémico (protocol version downgrade + null request ID). Stats CS01: 72 findings, 53 TP (73.6%), 19 FP (26.4%), FP rate mejoró 30.6%→26.4%
- **CS02 findings curados (F32-F51)** — remnux-mcp: 4 nuevos TP (scope-creep extract_archive, scope-creep download_file, supply-chain uuid, injection run_tool.input_file); token-exposure ×12 marcado como FP-dup (bug Corvus). docx-mcp: 4 TP (scope-creep write-path ×3, shadow tool `read_file`) + bulk FP note (injection echo by design, schema bypass permissivo)
- **Regresiones investigadas** — `ssh-mcp-server`: skip-env, requiere VM 301 running (hallazgos previos v0.9.x preservados). `korean-law-mcp`: skip-env permanente, external API unavailable en todos los scans. `remnux-mcp-server`: ERROR en summary.md era falso-negativo del Windows noise — report.json capturado correctamente

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
