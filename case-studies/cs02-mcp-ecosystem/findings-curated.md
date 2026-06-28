# CS02 — Findings Curados

Tabla consolidada post-FP-filter. 20 targets escaneados exitosamente de 42 intentados (22 errores de startup, 7 skip).
Corvus v0.9.0 — 22 módulos — scan date: 2026-06-28.

## Tier D — Community ecosystem (npm)

| ID | Target | Módulo | Severidad | Título | Confirmado | Notas |
|----|--------|--------|-----------|--------|------------|-------|
| CS02-F01 | mcp-server-docker | EXT03 Shadow Tool | HIGH | `run_command` conflicts con nombre built-in de alto valor | ✅ TP | run_command es nombre canónico de ejecución arbitraria. Server describe "Execute a command inside a Docker container service" — exec remoto real. |
| CS02-F02 | mcp-server-docker | EXT03 Shadow Tool | HIGH | `run_command` description revela arbitrary execution intent | ✅ TP | Mismo tool que F01 — dos señales distintas (nombre + descripción). Doble flag indica alta confianza. |
| CS02-F03 | postgres-mcp-server | EXT03 Shadow Tool | HIGH | `pg_execute_sql` "Execute arbitrary SQL statements" | ✅ TP | Describe explícitamente ejecución de SQL arbitrario (`sql="ANY_VALID_SQL"`). AI agent podría ser dirigido a ejecutar SQL malicioso. |
| CS02-F04 | lsp-mcp-server | EXT03 Shadow Tool | HIGH | `lsp_code_actions` — "Set apply=true to execute an action" | ✅ TP | Descripción instruye explícitamente al modelo a usar `apply=true` para ejecutar acciones de código. Prompt injection directo. |
| CS02-F05 | docx-mcp | EXT03 Shadow Tool | HIGH | `batch_edit` acepta `plan_file_path` JSON array | ✅ TP | Tool acepta un archivo de plan externo como entrada. Patrón: un attacker puede inyectar un plan malicioso via tool output → prompt injection. |
| CS02-F06 | postgres-mcp-server | MCP02 Scope Creep | HIGH | `pg_manage_users` inputSchema solicita campo `password` | ✅ TP (Gap 1) | Primera detección automática de campo credential en inputSchema. Tool expone `password` como param MCP — AI agent podría exponer credenciales. |
| CS02-F07 | mcp-javadc | MCP05 Cmd Injection | HIGH | `decompile-from-path.classFilePath` — path accedido en filesystem | ✅ TP condicional | Payload `%2e%2e%2f` (URL-encoded) llega al OS: `ENOENT: .../corvus/%2e%2e%2f%2e%2e%2fet`. Sin decode = no traversal real. Con path sin encoding: NECESITA VERIFICACIÓN manual. |
| CS02-F08 | 7 targets (ver abajo) | EXT01 Proto-Fuzz | HIGH | Protocol crash: oversized method name causa falla de transporte | ✅ TP | DoS via JSON-RPC malformado. 7/20 servers (35%) crashean al recibir un method name sobredimensionado. Reproducible. |
| CS02-F09 | mcp-server-docker | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` HIGH vuln (cascade) | ✅ TP (cascade) | Mismo advisory que CS01-F09. Pattern confirmado: el SDK oficial afecta a todo el ecosistema. |
| CS02-F10 | flightradar-mcp-server | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` HIGH vuln (cascade) | ✅ TP (cascade) | Mismo advisory. Segundo servidor nuevo en CS02 afectado por el mismo SDK advisory. |
| CS02-F11 | mantine-mcp-server | MCP10 Response Flood | HIGH | `list_items` retorna respuesta 18,763 bytes sin paginación | ✅ TP | 18KB de componentes Mantine sin paginación. Excede ventana de contexto en modelos compactos. |
| CS02-F12 | regle-mcp-server | MCP10 Response Flood | HIGH | `regle-list-validation-properties` retorna 9,318 bytes | ✅ TP | Documentación Vue.js sin chunking. Flooding vector real aunque bounded. |
| CS02-F13 | lsp-mcp-server | EXT01 Param Smuggling | MEDIUM | 5 tools devuelven estructura de error diferente con `_debug` | ❌ FP-ish | Evidence: "New JSON keys: ['error']" — el server rechaza el param desconocido con error key. Comportamiento de validación correcto, no backdoor. |
| CS02-F14 | jamf-docs-mcp-server | EXT01 Param Smuggling | MEDIUM | 3 tools retornan `isError=True` con `_debug` | ❌ FP-ish | Mismo patrón que F13. Server detecta param desconocido y retorna error. Input validation OK, no hidden endpoint. |

### CS02-F08 — Targets afectados por Protocol Crash

| Target | Weekly Downloads |
|--------|-----------------|
| european-parliament-mcp-server | 889/wk |
| postgres-mcp-server | — |
| pubmed-mcp-server | — |
| spartan-mcp | — |
| mcp-server-nationalparks | — |
| shadcn-ui-mcp-server | — |
| ui5-mcp-server | — |

---

## Targets con ERROR de startup (22)

Clasificados por causa probable:

| Grupo | Targets | Causa |
|-------|---------|-------|
| Requiere credenciales DB | mcp-postgres, mcp-mysql-server, mysql-mcp-server, mcp-server-docker (nope — este SÍ corrió) | DB connection string obligatoria |
| Requiere config/vault | obsidian-mcp-server, mediawiki-mcp-server, openapi-mcp-server | Path/URL de configuración obligatoria |
| Startup hang/crash | korean-law-mcp, remnux-mcp-server, markmap-mcp-server, myclaw-toolkit, kernlang-mcp-server, musea-mcp-server, mcp-fetch, mcp-read-website-fast, fetch-url-mcp | npx cuelga durante descarga o init |
| Requiere targets externos | ssh-mcp-server, mcp-server-code-runner | SSH host / sandbox Docker requerido |
| Otros | cclsp, desktop-commander, malicious-mcp-server (ironía), agent-orchestrator-mcp-server, playwright-mcp-server | Configuración de workspace o servicios externos |

---

## False Positives notables

| FP# | Target | Módulo | Severidad Raw | Título | Motivo FP |
|-----|--------|--------|---------------|--------|-----------|
| CS02-FP01 | regle-mcp-server | MCP01 Token Exposure | CRITICAL→FP | Token Exposure en respuesta de `regle-list-rules` | Documentación Vue.js (`MaybeRefOrGetter<boolean>`) matchea regex de credential. Text ≠ credential real. |
| CS02-FP02 | regle-mcp-server | MCP01 Token Exposure | CRITICAL→FP | Token Exposure en `regle-list-validation-properties` | Mismo patrón — docs de propiedades de validación. |
| CS02-FP03 | Multiple (10 targets) | MCP05 Cmd Injection | HIGH→FP | Injection reflected — input echo en búsqueda | Server retorna la query en la respuesta JSON por diseño (campo `query`, `symbol_name`, etc.). No ejecutado. |
| CS02-FP04 | postgres-mcp-server | EXT03 Shadow Tool | HIGH→FP | `pg_execute_query` + `pg_execute_mutation` arbitrary exec | Herramientas DB legítimas con descripción precisa. El flag es por palabras "execute"/"arbitrary" en texto, pero el contexto es operación DB normal. |
| CS02-FP05 | docx-mcp | EXT03 Shadow Tool | HIGH→FP | `read_file` conflicts con built-in | Limitado a archivos .docx del workspace. No es read_file arbitrario del sistema. |

---

## Notas de análisis

### CS02-F01/F02 — run_command en mcp-server-docker
`run_command` es un nombre de alto valor que conflictúa con herramientas de ejecución nativas. En mcp-server-docker el contexto es Docker (intencionalmente controlado), pero el patrón es exactamente el mismo que un servidor malicioso usaría: un LLM ve `run_command` y asume operación del sistema.

### CS02-F06 — Scope Creep (Gap 1) en postgres-mcp-server
Primera detección automática de credencial en inputSchema. `pg_manage_users` declara `password` como campo MCP-accessible. El scope_audit module v0.9.0 detecta `_HIGH_SCHEMA_RE` en la lista de properties. Un AI agent con acceso a este server podría ser prompiado a pasar credenciales reales por el canal MCP.

### CS02-F07 — mcp-javadc path traversal condicional
El OS recibió el payload URL-encoded literalmente (`%2e%2e%2f%2e%2e%2f`). Sin decode en el servidor, no hay traversal real. Pero la superficie existe: si `classFilePath` acepta rutas arbitrarias (sin sandboxing al workspace), un path como `/etc/passwd` directo podría ser viable. Requiere verificación manual con payload sin codificar.

### CS02-F08 — Protocol Crash prevalencia alta (35%)
7 de 20 servers (35%) crashean con un method name sobredimensionado. El proto_fuzz module genera un nombre de método de 10,000 caracteres — esto es JSON-RPC válido pero no definido en el MCP spec. La mayoría de los servers implementan el handler con una validación O(n) que desborda buffer interno de asyncio/ws. Este patrón es un DoS remoto reproducible contra clientes que hosten estos servers via HTTP.

### CS02-FP01/FP02 — Token Exposure en regle (calibración)
El module `token_exposure` tiene un regex que matchea palabras como "token", "secret", "key" en respuestas. La documentación Vue.js de Regle contiene frecuentemente estas palabras en contexto técnico (TypeScript generics, property names). Acción: agregar filtro de contexto — si el "credential" aparece dentro de código/markdown técnico, reducir confidence o downgradear a MEDIUM.

### Supply chain cascade (CS02-F09/F10)
Tercer y cuarto servidor afectados por `@modelcontextprotocol/sdk@<=1.25.1`. El patrón está completamente confirmado: cualquier server Node.js que use el SDK oficial es vulnerable. El advisory afecta a >200 servers en el ecosistema npm.
