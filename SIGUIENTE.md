# SIGUIENTE — Corvus

## Objetivo estratégico: Ekoparty 2026 Buenos Aires (7-9 oct)

Corvus es el framework con más chances de ser aceptado en Ekoparty. El ángulo: **primer scanner open source del OWASP MCP Top 10 — con datos reales**.
CFP abierto en Sessionize (track MainTrack + Red Team Space). **Deadline real: 14 agosto 2026** (no junio como se creía). Red Team Space 2026 CFP no anunciado aún — históricamente abre julio, cierra ~17 agosto.

Gap crítico a cerrar: **no hay case study contra targets reales aún**. Sin eso no hay charla.

---

## Bloque 0 — Deuda técnica pendiente (hacer antes de todo)

**Estado:** 4 commits en main local (7b1cc3d → cf96c28), tag v0.5.1 creado localmente. 64/64 tests pasan.

```powershell
cd sectors/red-team/corvus

# 1. Push commits + tag
git push origin main
git push origin v0.5.1

# 2. PyPI (token manual)
.venv/Scripts/twine.exe upload dist/cobaltosec_corvus-0.5.1*

# 3. GitHub release
gh release create v0.5.1 `
  --title "v0.5.1 — FP fixes for pydantic v2 + JSON-echo reflection" `
  --notes "Fixes false positives in schema-bypass (MCP05) and param-injection (MCP02)."
```

---

## Bloque 1 — Case Study: scan de MCP servers públicos reales (RT-CORVUS-CS01)

El hook de la charla es este bloque. Sin findings reales no hay propuesta.

### Targets candidatos (en orden de prioridad)

**Tier A — MCP servers oficiales @modelcontextprotocol (npm)**
Instalación: `npx -y @modelcontextprotocol/server-<name>`

| Server | Comando | Por qué es interesante |
|--------|---------|------------------------|
| `server-filesystem` | `npx -y @modelcontextprotocol/server-filesystem /tmp` | `read_file`/`write_file` → path traversal probable (MCP02) |
| `server-github` | `npx -y @modelcontextprotocol/server-github` | tool descriptions con markdown user-controlled → tool poisoning probable (MCP01) |
| `server-postgres` | `npx -y @modelcontextprotocol/server-postgres $DB_URL` | SQL injection via params (MCP02) |
| `server-sqlite` | `npx -y @modelcontextprotocol/server-sqlite /tmp/test.db` | mismo vector que postgres |
| `server-brave-search` | `npx -y @modelcontextprotocol/server-brave-search` | response flood con resultados (MCP07) |
| `server-git` | `npx -y @modelcontextprotocol/server-git` | command injection en git ops (MCP02 CRITICAL candidato) |

**Tier B — Community servers con muchas stars (GitHub topic `mcp-server`)**

Buscar en `https://github.com/topics/mcp-server?sort=stars` — tomar top 10 con ≥100 stars y escanear estáticamente primero (tool-poisoning + schema-audit sin ejecutar).

**Tier C — Smithery.ai catalogue**

Los MCP servers listados en smithery.ai son terceros — calidad variable, superficie interesante.

### Metodología del case study

```bash
# Por cada target:
# 1. Scan estático primero (seguro, sin side effects)
corvus scan --transport stdio --cmd "<cmd>" --module static --sarif

# 2. Scan dinámico completo
corvus scan --transport stdio --cmd "<cmd>" --sarif

# 3. Guardar sesión
# Sesiones quedan en corvus-sessions/<timestamp>/
```

### Output esperado del bloque

- Tabla de findings agregados por servidor y módulo
- Top 3 findings más impactantes con evidencia (report.json → snippets)
- Al menos 1 HIGH real confirmado manualmente (no FP)
- Estadísticas: % de servers con tool-poisoning, % con path traversal, etc.

### Archivo de resultados

Guardar en `case-studies/cs01-mcp-ecosystem/`:
```
case-studies/cs01-mcp-ecosystem/
├── methodology.md
├── targets.md          # tabla de targets escaneados con versión y fecha
├── findings-raw/       # report.json + report.md de cada scan
├── findings-curated.md # tabla curada, FPs filtrados manualmente
└── report.md           # case study final (narrativa + estadísticas)
```

---

## Bloque 2 — Mejoras framework v0.6.0 (RT-CORVUS-V06)

Identificadas vía análisis de Falcon + Shrike + benchmarks profesionales (2026-06-24).
Prerequisito para que CS01 produzca evidencia válida y la charla sea presentable.

### Críticas — sin esto CS01 no tiene evidencia verificable

**C1 — Request/Response capture** (`exchanges.jsonl`)
- Agregar `RawExchange = {method, params, response, duration_ms, ts}` a `ScanSession`
- Loguear en `StdioTransport.send_request()` y `HttpTransport.send_request()`
- Escribir `exchanges.jsonl` en `output_dir` junto con los reportes
- Flag `--log-requests` opcional
- **Archivos:** `corvus/transport/stdio.py`, `corvus/transport/http.py`, `corvus/models.py`
- **Esfuerzo:** 2h

**C2 — Stderr capture + startup validation**
- Leer stderr no-bloqueante 500ms después de crear el proceso
- Si el proceso muere antes del primer request → `ServerStartupError` con contenido de stderr
- Agregar `stderr_output` al reporte si hay contenido
- **Motivo:** `npx server-github` sin `GITHUB_TOKEN`, `server-postgres` sin DB_URL → cuelgan silenciosamente hoy
- **Archivos:** `corvus/transport/stdio.py`
- **Esfuerzo:** 1.5h

**C3 — Exploitation confirmation path traversal**
- Después de detectar reflection de `../etc/passwd`, buscar strings de contenido real: `root:x:0:0`, `nobody:`, `bin/bash`
- Si aparecen → CRITICAL con `exploitation_confirmed=True`. Si no → downgrade a MEDIUM
- **Archivos:** `corvus/modules/dynamic/param_injection.py`
- **Esfuerzo:** 2h

### Altas — mejoran exponencialmente el workflow de CS01

**A1 — Batch scan mode** (`corvus batch targets.yaml`)
- Nuevo comando que toma una lista `{name, cmd/url, transport}` y corre cada target en secuencia
- Escribe report individual por target en `output_dir/<name>/`
- Al final: `summary.md` con tabla agregada de findings por target y severidad + `summary.html` listo para slides
- **Archivos:** `corvus/cli/main.py`, nuevo `corvus/batch.py`
- **Esfuerzo:** 3h

**A2 — Finding confidence score + `--min-confidence` filter**
- Agregar `confidence: int` (0-100) a `Finding`
- Cada módulo asigna confidence según señales: exploitation_confirmed=True → 90, solo reflection → 50, regex pattern → 85, entropy → 20
- Flag `--min-confidence 60` filtra findings por debajo del umbral
- **Archivos:** `corvus/models.py`, todos los módulos
- **Esfuerzo:** 2h

**A3 — Entropy FP fix** (quick win — 30min)
- En `tool_poisoning.py`: threshold 4.5 → 5.0, solo disparar si `len(description) > 200`
- Alternativa: reemplazar entropy por detección de base64 (`[A-Za-z0-9+/]{40,}={0,2}`)
- **Archivos:** `corvus/modules/static/tool_poisoning.py`
- **Esfuerzo:** 30m

**A4 — Error-provoking en info-disclosure**
- Después de la llamada benigna, agregar: call con `args={}` (sin required params) + call con string 10k chars
- Ambas respuestas se analizan con `_SIGNALS` — stack traces aparecen en error paths
- **Archivos:** `corvus/modules/dynamic/info_disclosure.py`
- **Esfuerzo:** 1h

**A5 — Windows path traversal payloads** (quick win — 30min)
- Agregar sección `windows` en payloads: `..\..\windows\win.ini`, `C:\Windows\win.ini`, `..\windows\system32\drivers\etc\hosts`
- En `PayloadEngine.get_payloads()`, si `sys.platform == "win32"` → añadir payloads Windows para campos `path`
- **Archivos:** `corvus/payloads/traversal.yaml`, `corvus/engine.py`
- **Esfuerzo:** 30m

**A6 — FP validator info-disclosure** (de Falcon)
- Antes de emitir finding, validar content-type + body pattern
- Si server devuelve HTML catch-all (SPA) → descartar en lugar de reportar FP
- **Archivos:** `corvus/modules/dynamic/info_disclosure.py`
- **Esfuerzo:** 1h

**A7 — Rug Pull FP: stateful servers**
- `server-sequential-thinking` dispara MCP06 HIGH porque su tool list cambia por diseño (el server es stateful)
- Fix: en `rug_pull.py`, si el segundo `tools/list` devuelve 0 tools (server vacío por estado) en lugar de una lista diferente → downgrade a MEDIUM o skip
- Alternativa: añadir `--rug-pull-delay N` para esperar entre los dos `tools/list` calls y confirmar estabilidad
- **Motivo:** CS01 ya expuso este FP en server-sequential-thinking 0.2.0
- **Archivos:** `corvus/modules/dynamic/rug_pull.py`
- **Esfuerzo:** 1h

**A8 — CS01 Tier A: server-github con GITHUB_TOKEN**
- Escanear `npx -y @modelcontextprotocol/server-github` con token real (read-only scope)
- Superficie esperada: tools con repo names en descriptions → candidato MCP01 (tool poisoning vía markdown)
- Setup: crear GitHub token con scope `repo:read` para cuenta de prueba
- **Esfuerzo:** 30min setup + scan

**A9 — Enumeración con notificaciones listChanged**
- `server-everything` (y futuros servers dinámicos) expone 0 tools en el `tools/list` inicial
- El server anuncia que puede cambiar su lista via `tools.listChanged: true` en capabilities
- Fix: si el server declara `listChanged: true`, suscribirse a `notifications/tools/list_changed` y esperar hasta 5s antes de emitir surface vacía
- **Archivos:** `corvus/discovery/enumerator.py`, `corvus/transport/base.py`
- **Esfuerzo:** 2h

### Medias — para después de CS01

**M1 — SQLi error-based confirmation**
- Buscar en respuesta: `sqlite3.OperationalError`, `pg_exception_detail`, `SQLSTATE`, `syntax error`
- Si aparecen → CRITICAL con `exploitation_confirmed=True`
- Agregar payloads time-based: `'; SELECT pg_sleep(3)--`, medir response_time vs baseline
- **Esfuerzo:** 3h

**M2 — `deny_in_context` en param-injection** (de Shrike)
- Downgrade a LOW si la respuesta contiene señales de sanitización explícita (`"sanitized"`, `"filtered"`, `"escaped"`)
- **Esfuerzo:** 1h

**M3 — Proxy env var `CORVUS_PROXY`** (de Falcon)
- Leer env var en cliente httpx del HTTP transport
- Útil para interceptar con Burp en demos
- **Esfuerzo:** 20m

### Resumen de esfuerzo

| Grupo | Mejoras | Estado | Total |
|-------|---------|--------|-------|
| Críticas (C1-C3) | 3 | ✅ DONE v0.6.0 | — |
| Quick wins (A3+A5) | 2 | A5 ✅ DONE / A3 pendiente | ~30min |
| Resto altas (A1+A2+A4+A6) | 4 | Pendiente | ~7h |
| Nuevas altas (A7+A8+A9) | 3 | Pendiente | ~3.5h |
| Medias (M1-M3) | 3 | Pendiente | ~4h |

---

## Bloque 3 — Calibración post-CS01 (RT-CORVUS-V07)

Pulir FPs que CS01 exponga en targets reales:

- **info-disclosure calibración** — verificar si reflections tienen el mismo patrón isError + JSON echo que ya se corrigió en MCP02/MCP05
- **schema-bypass LOWs genuinos** — agregar remediation hint "use `ConfigDict(extra='forbid', strict=True)`" para pydantic v2
- **param-injection payloads adicionales** — agregar header injection (`\r\nX-Injected:`) y LDAP injection para ampliar cobertura

---

## Bloque 4 — Propuesta Ekoparty (RT-CORVUS-EKO01)

Una vez que CS01 tiene al menos 3 findings reales confirmados, redactar:

### Abstract (para Sessionize CFP)

**Título propuesto:** "Corvus: Automated OWASP MCP Top 10 Scanning — What We Found in 30 MCP Servers"

**Pitch (100 palabras):** MCP (Model Context Protocol) es el estándar emergente para conectar herramientas a LLMs. En 2025-2026, miles de servidores MCP se deployaron — la mayoría sin ningún security review. Desarrollé Corvus, el primer scanner open source del OWASP MCP Top 10. En esta charla presento los resultados de auditar 30+ MCP servers públicos: prompt injection oculta en tool descriptions, path traversal sin validación, SQL injection confirmado, y herramientas que mutan su superficie mid-session (rug pull). Demo en vivo incluida.

### Estructura de charla (35 min)

1. **Qué es MCP y por qué importa** (5 min) — el nuevo attack surface que todos están ignorando
2. **OWASP MCP Top 10** (8 min) — los 10 vectores con ejemplos concretos
3. **Corvus arquitectura** (7 min) — cómo funciona el scanner (stdio/HTTP, static+dynamic, SARIF)
4. **Case Study CS01** (10 min) — resultados reales: tabla de findings, top 3 en detalle
5. **Demo en vivo** (5 min) — scan de un server en tiempo real desde terminal

### Tracks a postular

1. **Red Team Space** — tool presentation, formato ideal para Corvus
2. **MainTrack** — si CS01 produce findings impactantes (≥1 HIGH en server oficial @modelcontextprotocol)

### Materiales a preparar

- [ ] Abstract en inglés y español
- [ ] Bio del speaker (Nicolás Padilla, CobaltoSec)
- [ ] Slides (30 slides máx — 1 por minuto)
- [ ] Demo environment preparado y testado
- [ ] Repo público limpio con README actualizado
- [ ] PyPI v0.5.1+ live

---

## Timeline estimado

| Bloque | Duración | Condición de éxito |
|--------|----------|--------------------|
| Bloque 0 (push/PyPI) | 1 sesión | v0.5.1 en GitHub + PyPI |
| Bloque 2 (mejoras framework) | 2-3 sesiones | C1-C3 implementadas, quick wins listos |
| Bloque 1 (Case Study CS01) | 2-3 sesiones | ≥3 HIGH reales documentados |
| Bloque 3 (calibración) | 1 sesión | FP rate < 10% en targets reales |
| Bloque 4 (propuesta Ekoparty) | 1 sesión | Abstract + outline listos |
| **Postulación** | — | CFP enviado antes de cierre **14 agosto 2026** |

---

## Qué NO hacer antes de Ekoparty

- No rediseñar el core de Corvus — está bien como está
- No agregar módulos nuevos sin case study que los motive
- No publicar findings sin coordinar disclosure con los maintainers de cada server (responsible disclosure si hay algo crítico)
