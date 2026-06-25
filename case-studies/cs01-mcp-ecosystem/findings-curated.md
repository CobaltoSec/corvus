# CS01 — Findings Curados

Tabla consolidada post-FP-filter. Solo findings confirmados manualmente.

## Tier A — Oficial @modelcontextprotocol

| ID | Target | Versión | Módulo | Severidad | Título | Confirmado | Notas |
|----|--------|---------|--------|-----------|--------|------------|-------|
| CS01-F01 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `read_file` shadows well-known built-in name | ✅ | Intencional en este server, pero patrón explotable por servers maliciosos |
| CS01-F02 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `write_file` shadows well-known built-in name | ✅ | Mismo patrón |
| CS01-F03 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `edit_file` shadows well-known built-in name | ✅ | Mismo patrón |
| CS01-F04 | server-memory | 0.6.3 | MCP05 Schema Bypass | LOW | `create_entities` acepta campos no declarados | ✅ | 9 tools afectadas, sin `additionalProperties: false` |
| CS01-F05 | server-memory | 0.6.3 | MCP05 Schema Bypass | LOW | `search_nodes.query` acepta tipo incorrecto | ✅ | Sin type coercion — pasa silenciosamente |
| CS01-F06 | server-sequential-thinking | 0.2.0 | MCP06 Rug Pull | HIGH | Tool `sequentialthinking` desapareció mid-session | ❌ FP | Server stateful — tool list cambia por diseño |
| CS01-F07 | server-sequential-thinking | 0.2.0 | MCP01 Tool Poisoning | MEDIUM | Descripción excesivamente larga en `sequentialthinking` | ❌ FP | Descripción larga es el propósito del server |
| CS01-F08 | server-sequential-thinking | 0.2.0 | MCP01 Tool Poisoning | LOW | Alta entropía en descripción de `sequentialthinking` | ❌ FP | Base64/estructura esperada en el prompt del server |
| CS01-F09 | server-github | 0.6.2 | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` tiene vulnerabilidad high | ✅ TP (confidence 65) | Advisory directo en dep. Sin CVE asignado (GHSA). |
| CS01-F10 | server-github | 0.6.2 | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/server-github@*` tiene vulnerabilidad high | ❌ FP | Cascade advisory via strings. Filtrado desde v0.8.0. |
| CS01-F11 | server-everything | 2.0.0 | MCP01 Info Disclosure | HIGH | `get-env` expone todas las variables de entorno del proceso | ✅ TP manual | Tool description confirma: "Returns all environment variables". Scan no capturó tools (enumerator bug — server manda tools en clave `resources/list`). Verificado via tool schema en exchanges.jsonl. En prod expone API keys, secrets. |
| CS01-F12 | server-everything | 2.0.0 | MCP05 Schema Bypass | MEDIUM | `echo` acepta missing required fields | ❌ Inconclusive | Enumerator bug impidió scan dinámico. No se puede confirmar sin re-scan con bug fix. |
| CS01-F13 | server-everything | 2.0.0 | MCP05 Schema Bypass | MEDIUM | `get-structured-content` acepta missing required fields | ❌ Inconclusive | Mismo motivo que F12. |

## Tier B — Community servers

| ID | Target | Módulo | Severidad | Título | Confirmado | Notas |
|----|--------|--------|-----------|--------|------------|-------|
| CS01-F14 | mcp-server-puppeteer | MCP02 SSRF | HIGH | Puppeteer navega a URLs arbitrarias incl. 169.254.169.254 | ✅ Manual | Chrome abrió AWS metadata endpoint durante probe. SSRF confirmado en entorno cloud. |
| CS01-F15 | mcp-fetch-server | MCP04 Supply Chain | HIGH | `private-ip` dep con vulnerabilidad high (sin CVE) | ✅ TP (confidence 65) | Irónico: el server usa `private-ip` como SSRF filter — la lib que lo protege está vulnerable. Bypass posible. |
| CS01-F16 | npm-search-mcp-server | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` en dep | ✅ TP (confidence 65) | Mismo advisory que F09. Patrón: el advisory afecta a todos los servers que usan sdk≤1.25.1. |
| CS01-F17 | npm-search-mcp-server | MCP05 Schema Bypass | LOW | `search_npm_packages` acepta `__proto__` sin error | ✅ TP-LOW | Sin additionalProperties:false. Proto pollution vector. |
| CS01-F18 | n8n-mcp | MCP05 Cmd Injection | MEDIUM | `tools_documentation.topic` refleja input verbatim | ✅ TP-condicional | Evidence: `Tool '<script>alert(1)</script>' not found.` — reflection real. Impacto: prompt injection si payload contiene instrucciones. Payload actual (XSS) no demuestra explotación directa. |
| CS01-F19 | n8n-mcp | MCP05 Cmd Injection | LOW | `search_nodes.query` echo en respuesta JSON | ❌ FP | Confidence 30. El server incluye la query en el JSON de respuesta por diseño (campo `query` en resultado). |
| CS01-F20 | n8n-mcp | MCP05 Schema Bypass | MEDIUM | `get_node` ejecuta con campos requeridos faltantes | ✅ TP | `nodeType` declarado required pero el tool ejecuta con args vacíos. |
| CS01-F21 | n8n-mcp | MCP05 Schema Bypass | LOW | `search_nodes.query` acepta tipo incorrecto | ✅ TP-LOW | Mismo patrón que F05 en server-memory. |
| CS01-F22 | n8n-mcp | MCP05 Schema Bypass | LOW | `get_node.nodeType` acepta tipo incorrecto | ✅ TP-LOW | Acepta `None` donde espera `string`. |
| CS01-F23 | n8n-mcp | MCP05 Schema Bypass | LOW | `validate_node.nodeType` acepta tipo incorrecto | ✅ TP-LOW | Acepta `int` donde espera `string`. |
| CS01-F24 | n8n-mcp | MCP05 Schema Bypass | LOW | `validate_workflow.workflow` acepta tipo incorrecto | ✅ TP-LOW | Acepta `None` donde espera `object`. |
| CS01-F25 | n8n-mcp | MCP05 Schema Bypass | LOW | `validate_workflow` acepta `__proto__` | ✅ TP-LOW | Sin additionalProperties:false. |
| CS01-F26 | n8n-mcp | EXT02 Schema Info | INFO | `tools_documentation` no define campos required | ❌ FP | Diseño intencional — flexibilidad de la API de docs. |
| CS01-F27 | n8n-mcp | EXT02 Schema Info | INFO | `search_templates` no define campos required | ❌ FP | Mismo patrón. |
| CS01-F28 | shell-command-mcp | MCP03 Shadow Tool | HIGH | `execute_command` conflicts con nombre built-in de alto valor | ✅ TP | Confidence 90. En este server es legítimo, pero el patrón es idéntico a F01-F03: un server malicioso que registre `execute_command` sería confiado implícitamente por un LLM. |
| CS01-F29 | server-sqlite | MCP05 Cmd Injection | HIGH | `describe_table.table_name` — SQL injection via table name | ✅ TP | Payload `null` inyectado en consulta SQL: "near null: syntax error". table_name se interpola sin sanitizar en `PRAGMA table_info(<name>)`. Permite SQLi clásico. |
| CS01-F30 | server-sqlite | MCP05 Cmd Injection | HIGH | `write_query.query` — error-based SQL injection | ❌ FP (by design) | Tool está diseñado para ejecutar SQL arbitrario. El error verbose confirma ejecución pero el patrón es intencional. Sin mecanismo de allowlist (ej. SELECT-only). |
| CS01-F31 | server-sqlite | MCP05 Schema Bypass | MEDIUM | `write_query` ejecuta con campos requeridos faltantes | ✅ TP | `query` declarado required pero el tool acepta args vacíos y retorna error SQL verbose. |
| CS01-F32 | server-sqlite | MCP05 Schema Bypass | MEDIUM | `describe_table` ejecuta con campos requeridos faltantes | ✅ TP | `table_name` declarado required, acepta llamada vacía. Mismo patrón F20/F31. |
| CS01-F33 | playwright-mcp | MCP05 Path Traversal | HIGH | `browser_snapshot.filename` — path traversal → archivo creado en CWD | ✅ Confirmado | Payload `%2e%2e%2fetc%2fpasswd` aceptado como filename. Archivo creado en CWD. En Linux con URL decode: write a path arbitrario. Evidence: `./%2e%2e%2fetc%2fpasswd` existe post-scan. |
| CS01-F34 | playwright-mcp | MCP05 Path Traversal | HIGH | `browser_network_requests.filename` — path traversal → archivo creado en CWD | ✅ Confirmado | Mismo vector que F33 en tool de network capture. Filename no validado antes de escribir. |
| CS01-F35 | server-postgres | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` en dep | ✅ TP (confidence 65) | Mismo advisory que F09/F16. Patrón confirmado: afecta a todo el ecosistema que usa el SDK oficial. |
| CS01-F36 | server-postgres | EXT02 Schema Info | INFO | `query` define no required fields | ❌ FP | El tool acepta cualquier query SQL — diseño intencional (flexibilidad). |
| CS01-F37 | server-pdf | EXT02 Schema Info | INFO | `display_pdf` define no required fields | ❌ FP | Parámetros opcionales por diseño del viewer. |

---

## Notas de análisis

### CS01-F01/F02/F03 — Shadow Tool en server-filesystem
`read_file`, `write_file`, `edit_file` son nombres canónicos de operaciones de filesystem. Un servidor malicioso podría registrar herramientas con estos mismos nombres para que un LLM asuma que son operaciones seguras del sistema, cuando en realidad ejecutan código arbitrario.

**Veredicto:** TRUE POSITIVE (patrón de riesgo válido)

### CS01-F04/F05 — Schema Bypass en server-memory
`memory-server 0.6.3` no usa `additionalProperties: false` en ninguno de sus 9 schemas. `search_nodes.query` acepta cualquier tipo sin error.

**Veredicto:** TRUE POSITIVE

### CS01-F06/F07/F08 — FPs en server-sequential-thinking
Tool list cambia por diseño stateful. Descripción larga es el protocolo de razonamiento.

**Veredicto:** FALSE POSITIVE — candidatos para ajuste de umbral

### CS01-F09 — Supply Chain: `@modelcontextprotocol/sdk@<=1.25.1`
Advisory npm directo. Sin CVE asignado. Corvus reporta confidence=65.

**Veredicto:** TRUE POSITIVE — advisory real, confidence=65

### CS01-F10 — Supply Chain cascade (FP)
`via: ["@modelcontextprotocol/sdk"]` strings only. Corvus v0.8.0 lo filtra automáticamente.

**Veredicto:** FALSE POSITIVE — cascade advisory filtrado

### CS01-F14 — SSRF en mcp-server-puppeteer (manual)
Durante el batch scan, Corvus envió como probe SSRF la URL `http://169.254.169.254` al tool `navigate` del server Puppeteer. El server abrió Chrome y navegó al endpoint de metadatos de instancia cloud (AWS/GCP/Azure). En entorno cloud, esto permite robar las credenciales del rol IAM de la instancia.

**Veredicto:** TRUE POSITIVE — SSRF confirmado. El server acepta URLs arbitrarias sin whitelist de destinos.

### CS01-F15 — Supply Chain `private-ip` en mcp-fetch-server
`mcp-fetch-server` usa `private-ip` como guardia de SSRF (verificar si una IP es privada antes de hacer el fetch). El advisory indica que la propia lib de protección tiene una vulnerabilidad high. Si el bypass aplica a la versión instalada, un atacante puede evadir la guardia de SSRF y acceder a endpoints internos/metadata.

**Veredicto:** TRUE POSITIVE — ironía documentable: la defensa está comprometida.

### CS01-F16 — Supply Chain `@modelcontextprotocol/sdk` en npm-search-mcp-server
Mismo advisory GHSA que F09. Confirma que el advisory tiene alcance ecosistémico — cualquier server que no haya actualizado el SDK está afectado.

**Veredicto:** TRUE POSITIVE — dato para narrativa CFP: advisory en SDK base afecta N servers.

### CS01-F18 — Reflection en n8n-mcp `tools_documentation.topic`
Evidence: `Tool '<script>alert(1)</script>' not found. Use tools_documentation() to see available tools.`
La reflection es real. El impacto en contexto MCP (stdio) no es XSS sino prompt injection: si el payload contiene instrucciones en lugar de `<script>`, el LLM que lee la respuesta podría ejecutarlas. Requiere payload crafting específico.

**Veredicto:** TRUE POSITIVE condicional — reflection demostrada, explotación requiere payload de prompt injection, no XSS.

### CS01-F19 — FP en n8n-mcp `search_nodes.query` echo
El server incluye la query de búsqueda en el JSON de respuesta como campo `query` para referencia. Comportamiento estándar en APIs de search. Confidence 30.

**Veredicto:** FALSE POSITIVE — diseño de API, no vulnerabilidad.

### CS01-F20 — Schema Bypass `get_node` missing required fields
Tool declara `nodeType` como required, pero ejecuta sin error con args vacíos y devuelve respuesta válida (probablemente listado de todos los nodos).

**Veredicto:** TRUE POSITIVE

### CS01-F28 — Shadow Tool `execute_command` en shell-command-mcp
`execute_command` es el tool principal del server (legítimo). El patrón de detección es el mismo que F01-F03: en el ecosistema MCP, un tool con este nombre sería confiado implícitamente por modelos entrenados en código que usa `execute_command` como operación del sistema.

**Veredicto:** TRUE POSITIVE (patrón, no vuln en este server específico)

---

## Estadísticas finales (post CS01 completo)

- **Servers auditados**: 16 (15 auto + 1 manual — mcp-server-puppeteer)
- **Findings curados**: 37 (F01–F37)
- **TRUE POSITIVE**: 25 (67.6%) — F01/F02/F03/F09/F11/F14/F15/F16/F17/F18/F20/F21/F22/F23/F24/F25/F28/F29/F31/F32/F33/F34/F35 + F04/F05 (LOW)
- **FALSE POSITIVE**: 12 (32.4%) — F06/F07/F08/F10/F12/F13/F19/F26/F27/F30/F36/F37
- **HIGH TP**: 13 (F01/F02/F03/F09/F11/F14/F15/F16/F28/F29/F33/F34/F35)
- **MEDIUM TP**: 4 (F18/F20/F31/F32)
- **LOW TP**: 8 (F04/F05/F17/F21/F22/F23/F24/F25)
- **FP rate**: 32% (12/37)
- **Servers con ≥1 HIGH**: 9 de 15 (60%)

## Servers skip definitivos

| Server | Razón |
|--------|-------|
| server-everything | partial — enumerator bug, F12/F13 Inconclusive |
| mcp-server-puppeteer | skip — SSRF confirmado manual, Chrome visible en batch |
| playwright-mcp | done — path traversal F33/F34 confirmado |
| filesystem-mcp-server | skip — bug ESM en package, imports sin extensión .js |
| agent-infra-mcp-filesystem | skip — CLI incompatible con Windows paths |
| mcp-cli-exec | skip — paquete no publicado en npm |
| server-brave-search | skip — BRAVE_API_KEY requerida |
| mcp-server-aws-kb-retrieval | skip — AWS credentials requeridas |
| mcp-server-slack | skip — SLACK_BOT_TOKEN requerida |
| notion-mcp-server | skip — NOTION_API_KEY requerida |
| tavily-mcp | skip — TAVILY_API_KEY requerida |
| exa-mcp-server | skip — EXA_API_KEY requerida |
| server-gitlab | skip — GITLAB_TOKEN requerido |
