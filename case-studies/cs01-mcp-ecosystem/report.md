# CS01 — OWASP MCP Ecosystem Audit

**Framework:** Corvus v0.8.1  
**Período:** Junio 2026  
**Targets:** 35 MCP servers (10 Tier A @modelcontextprotocol + 16 Tier B community + 9 Tier C expansión)  
**Auditados:** 23 (16 Tier A+B + 7 Tier C auto; 2 Tier C skip)  
**Findings totales:** 51 (36 TP / 15 FP · FP rate 29%)

---

## Resumen ejecutivo

Escaneamos 23 MCP servers del ecosistema real — servidores usados en producción por miles de agentes LLM — con Corvus v0.8.1. Resultado: **15 de 23 servidores tienen al menos un finding HIGH confirmado (65%)**. El problema más sistémico es de supply chain: el advisory de `@modelcontextprotocol/sdk@<=1.25.1` afecta a ≥5 servidores del ecosistema. El más llamativo es un SSRF confirmado en `mcp-server-puppeteer` que navega al endpoint de metadata de AWS. Highlight de la expansión Tier C: `server-everything` ahora detecta **CRITICAL Token Exposure** automáticamente tras el fix del transport en v0.8.1.

---

## Metodología

Corvus v0.8.0 ejecuta 12 módulos contra cada target:

| Módulo | OWASP ID | Tipo |
|--------|----------|------|
| scope-audit | MCP02 | static |
| supply-chain | MCP04 | static |
| tool-poisoning | MCP01 | static |
| schema-audit | EXT02 | static |
| shadow-tool | MCP03 | static |
| auth-audit | MCP07 | static |
| log-audit | MCP08 | static |
| cmd-injection | MCP05 | dynamic |
| token-exposure | MCP01 | dynamic |
| schema-bypass | EXT01 | dynamic |
| response-flood | MCP09 | dynamic |
| rug-pull | MCP06 | dynamic |

**Transports probados:** stdio (npx/uvx) y HTTP (JSON + SSE).  
**SSE support:** Corvus v0.8.1 agrega `Accept: application/json, text/event-stream` — server-pdf ahora scaneable. Browsers (`playwright-mcp`, `mcp-server-puppeteer`) requieren scan manual (abren Chrome visible).

---

## Findings confirmados por servidor

### Tier A — @modelcontextprotocol

#### server-filesystem · 3 HIGH (Shadow Tool)
`read_file`, `write_file`, `edit_file` son nombres canónicos de filesystem. Un servidor malicioso que registre estas mismas tools sería confiado implícitamente por un LLM, que asumiría que ejecuta operaciones de sistema. Patrón de riesgo válido incluso cuando la implementación es legítima (F01–F03).

#### server-everything · 1 CRITICAL, 1 HIGH (Token Exposure + Response Flooding)
`get-env` — descripción: *"Returns all environment variables, helpful for debugging MCP server configuration"*. En producción expone API keys, tokens y rutas sensibles del proceso.

**v0.8.1 transport fix:** `server-everything` tiene `listChanged: true` y emitía `notifications/tools/list_changed` antes de responder a `tools/list`. El transport de Corvus leía la notificación como respuesta (result=null) → 0 tools capturadas. Fix: `send_request()` ahora loopea por `id`, skipea notificaciones. Post-fix: **13 tools capturadas, 1 CRITICAL + 1 HIGH detectados automáticamente.**

- **CRITICAL (F11):** `get-env` → Token Exposure (conf=85). Auto-detectado por el módulo `token-exposure`.
- **HIGH (F38):** `get-env` → Response Flooding (conf=85). Dump completo de env vars puede superar MB en entornos cloud con muchas variables.

#### server-github · 1 HIGH (Supply Chain)
`@modelcontextprotocol/sdk@<=1.25.1` tiene un advisory npm (GHSA, sin CVE asignado aún). Confidence 65 — advisory directo en dependencia. Patrón sistémico: cualquier server que use el SDK oficial en versiones antiguas hereda este finding.

#### server-sqlite · 2 HIGH, 2 MEDIUM (SQL Injection + Schema Bypass)
`describe_table.table_name` acepta input sin sanitizar, interpolado en `PRAGMA table_info(<name>)`. Payload `null` produce error SQL verbose: *"near null: syntax error"*. La tabla también acepta llamadas sin campos requeridos (F31–F32).

`write_query.query` clasificado como FP: el tool está diseñado para ejecutar SQL arbitrario — injection is the feature. Sin embargo, la ausencia de restricciones de operación (allowlist SELECT/INSERT only) sería una mejora.

#### server-git · 5 LOW (Schema Quality)
Clean desde perspectiva de seguridad. 5 LOW de schema-audit: parámetros sin type constraint en `git_log`, `git_create_branch`, `git_branch`. No hay cmd injection, supply chain ni shadow tools.

#### server-postgres · 1 HIGH (Supply Chain)
`@modelcontextprotocol/sdk@<=1.25.1` — mismo advisory que F09/F16. Patrón ecosistémico confirmado: el SDK oficial afecta a todos los servers que no actualizaron. Test env: Docker postgres:15 local.

#### server-pdf · 1 INFO (clean)
PDF Server 2.0.0. 4 tools. Clean desde perspectiva de seguridad. 1 INFO: `display_pdf` sin required fields (diseño intencional). Warning manual en startup: `binding to 0.0.0.0 without DNS rebinding protection` — el server no tiene protección contra DNS rebinding.

**Nota de framework:** Escaneado tras fix SSE en Corvus v0.8.1 — el transport HTTP ahora soporta `text/event-stream`.

---

### Tier B — Community servers

#### mcp-server-puppeteer · 1 HIGH (SSRF — manual confirm)
Durante el probe de SSRF, Corvus envió `http://169.254.169.254` como URL a `navigate`. El server levantó Chrome y navegó al endpoint de metadata de instancia (AWS/GCP/Azure). **En un entorno cloud, esto permite exfiltrar las credenciales IAM del rol de la instancia.**

El server acepta URLs arbitrarias sin whitelist de destinos. No hay validación de IPs privadas ni metadata endpoints. Chrome se abrió visiblemente durante el scan (razón por la que está marcado skip en batch).

#### mcp-fetch-server · 1 HIGH (Supply Chain)
`private-ip@*` tiene advisory npm HIGH. La ironía: `mcp-fetch-server` usa esta librería como **guardia de SSRF** (verificar si una IP es privada antes de hacer el fetch). La librería que protege contra SSRF está ella misma vulnerable. Si el bypass aplica a la versión instalada, la guardia puede eludirse.

#### npm-search-mcp-server · 1 HIGH (Supply Chain)
`@modelcontextprotocol/sdk@<=1.25.1` — mismo advisory que F09 en server-github. Patrón ecosistémico.

#### n8n-mcp · 1 HIGH (Supply Chain, pendiente curar), 1 MEDIUM (Cmd Injection)
`tools_documentation.topic` refleja input verbatim: *"Tool `<script>alert(1)</script>` not found."*. Reflection real — impacto como prompt injection si el payload contiene instrucciones en lugar de XSS. HIGH del raw scan pendiente de curar (probable supply chain via sdk).

#### shell-command-mcp · 1 HIGH (Shadow Tool)
`execute_command` — confidence 90. El tool es legítimo en este server (ejecuta comandos con allowlist configurable), pero el nombre `execute_command` es de alto valor: un server malicioso que lo registre sería confiado implícitamente por un agente LLM, que asumiría que opera dentro de los permisos del sistema.

#### playwright-mcp · 5 HIGH, 1 MEDIUM (Path Traversal + Injection)
**Finding destacado:** `browser_snapshot.filename` y `browser_network_requests.filename` aceptan path traversal URL-encoded sin validación. Payload `%2e%2e%2fetc%2fpasswd` enviado → archivo `%2e%2e%2fetc%2fpasswd` creado físicamente en el CWD del server durante el scan (evidenciado por su existencia en `case-studies/cs01-mcp-ecosystem/`).

En Linux, si el server decodifica el URL-encoding antes de escribir, el archivo se escribiría como `../../etc/passwd` relativo al working directory — potencial sobrescritura. En Windows, escribe con el nombre literal URL-encoded.

Además: `browser_evaluate.function` refleja el payload (probable FP para un server de JS execution). `browser_network_requests.filter` intentó navegación gopher:// — ERR_ABORTED por Chrome, no por el server (el server no valida el protocolo).

---

### Tier C — Expansión (shell servers + DB + network)

9 targets agregados en RT-CORVUS-V12. 7/9 auditados exitosamente. 2 skip definitivos: `@contextware/mcp-scan` (CLI interactivo, no MCP server) y `docker-mcp-server` (HTTP :30000 con auth-token dinámico por sesión).

#### Shell execution servers · patrón de injection sistémico

Tres servers de shell execution probados — `super-shell-mcp`, `@mako10k/mcp-shell-server`, `shell-command-mcp` (Tier B) — exhiben el mismo patrón:

- **Shadow tool HIGH:** Tools llamadas `execute_command` (conf=90) — LLMs los tratan como operaciones del sistema (F28, F39).
- **Injection reflected HIGH:** Parámetros de path/command reflejan payload verbatim en respuesta sin sanitizar: `shell_set_default_workdir.working_directory` (F42), `command_history_query.entry_id` (F43), `remove_from_whitelist.command` (F40).

Patrón: los servers de shell son el vector MCP más riesgoso. Ninguno implementa allowlist de comandos en la capa MCP; la defensa depende de configuración externa.

#### database-server-executeautomation · 4 HIGH (Supply Chain + Flooding)

- Supply chain HIGH en el propio package (`@executeautomation/database-server`) y en `tar@<=6.2.1` — `tar` es una utilidad del sistema ampliamente usada (F47, F48).
- `list_insights` sin paginación: dump completo en memoria → response flooding (F49).
- `@modelcontextprotocol/sdk` advisory (patrón ecosistémico).

#### mcp-server-mysql · 2 HIGH (Supply Chain)

- `undici@<6.x` HIGH — HTTP client de Node.js con CVEs publicados. Afecta a todo el stack de red del server (F50).
- `@modelcontextprotocol/sdk` advisory.

#### mcp-homescan · 2 MEDIUM (Injection + Schema)

Network scanner MCP. `homescan_device.ip` no validado — reflection en respuesta (F45). Combinación con scope creep: un server MCP de network scan con injection en el parámetro `ip` permite a un actor malicioso escanear IPs arbitrarias, incluyendo subredes internas del host donde corre el agente.

#### mcp-server-time · CLEAN

Sin findings. Superficie minimal (get_current_time + convert_time). Referencia positiva de server bien scoped.

---

## Patrones transversales

### 1. Supply chain sistémico
`@modelcontextprotocol/sdk@<=1.25.1` afecta a `server-github`, `npm-search-mcp-server`, `n8n-mcp` y otros. El advisory ecosistémico de MCP es una vulnerabilidad de tipo "blast radius" — actualizar el SDK en todos los servers es el fix.

### 2. Schema laxo en 8+ servers
`additionalProperties: false` ausente, campos `required` que se ignoran, tipos aceptados sin coerción. Patrón omnipresente. Los servers aceptan `__proto__`, `None` donde esperan `string`, args vacíos donde el schema declara required. Sin error. Sin log.

### 3. Shadow tool pattern en servers de filesystem/shell
Cualquier server que registre tools con nombres como `read_file`, `write_file`, `execute_command` — incluso si su implementación es legítima — normaliza que un LLM confíe en esos nombres. Un server malicioso registrado luego se beneficia de esa confianza implícita.

### 5. Shell execution servers = injection vector sistémico
Los tres shell servers auditados (Tier B + C) comparten el mismo patrón: parámetros de path/command reflejan payload sin sanitizar. Sin allowlist de comandos en la capa MCP. El protocolo no tiene primitivas de sandboxing — la defensa depende 100% de configuración del operador.

### 4. Browser servers como vectores de alto riesgo
`mcp-server-puppeteer` y `playwright-mcp` tienen acceso a un browser real. SSRF via URLs arbitrarias, path traversal via filenames, JS injection — el MCP protocol no tiene primitivas para restringir estas operaciones.

---

## FP Rate y calibración

**FP rate: 29%** (15 de 51 findings). Los FPs más comunes:
- Rug pull en servers stateful por diseño (`server-sequential-thinking`)
- Tool poisoning FP por descripciones largas legítimas (protocolo de razonamiento)
- Cascade supply chain advisories (filtrado en v0.8.0)
- `write_query` injection FP (el tool IS the injection)
- `browser_evaluate` reflection FP (evalúa JS por diseño)

El FP rate del 29% es aceptable para un scanner automático en v0.8.0. La mayoría de los FPs son detectables con contexto del server. Calibración futura: módulo context-aware que ajuste umbral según tipo de server.

---

## Limitaciones del framework descubiertas en CS01

| Limitación | Impacto | Fix |
|-----------|---------|-----|
| ~~HTTP SSE transport no soportado~~ | ~~server-pdf no escaneado~~ | **Resuelto en v0.8.1** |
| ~~Enumerator bug notificaciones intermedias~~ | ~~server-everything: 0 tools~~ | **Resuelto en v0.8.1** — transport skipea notificaciones por id |
| Browsers no escaneables en batch | puppeteer/playwright solo manual | Headless scan option |
| docker-mcp-server HTTP/auth-token dinámico | no auto-scannable en batch | Setup manual: capturar token de stderr + `--header` |
| Servers de API key (brave, slack, gitlab...) | 10 servers skip | Integration env vars / mock mode |

---

## Stats finales

| Métrica | Valor |
|---------|-------|
| Targets en scope | 35 |
| Auditados | 23 (16 Tier A+B + 7 Tier C) |
| Findings totales | 51 |
| True Positives | 36 (70.6%) |
| False Positives | 15 (29.4%) |
| CRITICAL TPs | 1 (F11 — Token Exposure auto) |
| HIGH TPs | 21 |
| MEDIUM TPs | 6 |
| LOW TPs | 8 |
| Servers con ≥1 HIGH | 15 de 23 (65%) |
| SDK advisory alcance | ≥5 servers del ecosistema |
| OWASP IDs cubiertos | MCP01, MCP02, MCP03, MCP04, MCP05, MCP06, MCP07, MCP08, MCP09, EXT01, EXT02, EXT03 |

---

*Generado con [Corvus](https://github.com/CobaltoSec/corvus) v0.8.1*
