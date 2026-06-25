# CS01 — OWASP MCP Ecosystem Audit

**Framework:** Corvus v0.8.0  
**Período:** Junio 2026  
**Targets:** 26 MCP servers (10 Tier A @modelcontextprotocol + 16 Tier B community)  
**Auditados:** 16 (15 via Corvus automatizado + 1 manual — mcp-server-puppeteer)  
**Findings totales:** 37 (25 TP / 12 FP · FP rate 32%)

---

## Resumen ejecutivo

Escaneamos 13 MCP servers del ecosistema real — servidores usados en producción por miles de agentes LLM — con Corvus v0.8.0. Resultado: **9 de 15 servidores tienen al menos un finding HIGH confirmado (60%)**. El problema más sistémico es de supply chain: el advisory de `@modelcontextprotocol/sdk@<=1.25.1` afecta a múltiples servidores del ecosistema. El más llamativo es un SSRF confirmado en `mcp-server-puppeteer` que navega al endpoint de metadata de AWS.

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

#### server-everything · 1 HIGH (Info Disclosure)
`get-env` — descripción: *"Returns all environment variables, helpful for debugging MCP server configuration"*. En producción expone API keys, tokens y rutas sensibles del proceso. Finding confirmado por inspección manual; el enumerador de Corvus no capturó las tools por un bug de parseo (el server responde con keys erróneas en tools/list → enumerador recibe null).

**Bug de framework documentado:** `server-everything` envía tools en la respuesta de `resources/list` y resources en `prompts/list`. Corvus espera la estructura MCP estándar. Fix pendiente en el enumerador.

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

## Patrones transversales

### 1. Supply chain sistémico
`@modelcontextprotocol/sdk@<=1.25.1` afecta a `server-github`, `npm-search-mcp-server`, `n8n-mcp` y otros. El advisory ecosistémico de MCP es una vulnerabilidad de tipo "blast radius" — actualizar el SDK en todos los servers es el fix.

### 2. Schema laxo en 8+ servers
`additionalProperties: false` ausente, campos `required` que se ignoran, tipos aceptados sin coerción. Patrón omnipresente. Los servers aceptan `__proto__`, `None` donde esperan `string`, args vacíos donde el schema declara required. Sin error. Sin log.

### 3. Shadow tool pattern en servers de filesystem/shell
Cualquier server que registre tools con nombres como `read_file`, `write_file`, `execute_command` — incluso si su implementación es legítima — normaliza que un LLM confíe en esos nombres. Un server malicioso registrado luego se beneficia de esa confianza implícita.

### 4. Browser servers como vectores de alto riesgo
`mcp-server-puppeteer` y `playwright-mcp` tienen acceso a un browser real. SSRF via URLs arbitrarias, path traversal via filenames, JS injection — el MCP protocol no tiene primitivas para restringir estas operaciones.

---

## FP Rate y calibración

**FP rate: 32%** (12 de 37 findings). Los FPs más comunes:
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
| Enumerator bug con keys no-estándar | server-everything: 0 tools capturadas | Parseo tolerante en tools/resources/prompts |
| Browsers no escaneables en batch | puppeteer/playwright solo manual | Headless scan option |
| Servers de API key (brave, slack, gitlab...) | 10 servers skip | Integration env vars / mock mode |

---

## Stats finales

| Métrica | Valor |
|---------|-------|
| Targets en scope | 26 |
| Auditados | 16 (15 auto + 1 manual) |
| Findings totales | 37 |
| True Positives | 25 (67.6%) |
| False Positives | 12 (32.4%) |
| HIGH TPs | 13 |
| MEDIUM TPs | 4 |
| LOW TPs | 8 |
| Servers con ≥1 HIGH | 9 de 15 (60%) |
| OWASP IDs cubiertos | MCP01, MCP03, MCP04, MCP05, MCP06, MCP08, EXT01, EXT02, EXT03 |

---

*Generado con [Corvus](https://github.com/CobaltoSec/corvus) v0.8.0*
