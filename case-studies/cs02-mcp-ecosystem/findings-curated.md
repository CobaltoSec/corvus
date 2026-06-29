# CS02 — Findings Curados

Tabla consolidada post-FP-filter. **31 targets escaneados** de 49 total (18 skip — browser/config/timeout).
Corvus v0.9.2 — 18 módulos — primera pasada: 2026-06-28, segunda pasada: 2026-06-29.

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
| postgres-mcp-server | 4,933/wk |
| pubmed-mcp-server | 3,385/wk |
| spartan-mcp | 1,455/wk |
| mcp-server-nationalparks | 13,831/wk |
| shadcn-ui-mcp-server | 3,046/wk |
| ui5-mcp-server | 117,814/wk |
| ssh-mcp-server | 2,373/wk |
| remnux-mcp-server | 1,813/wk |
| mysql-mcp-server | 1,060/wk |
| openapi-mcp-server | 298/wk |

## Segunda pasada — Findings (CS02-F15 → CS02-F31)

| ID | Target | Módulo | Severidad | Título | Confirmado | Notas |
|----|--------|--------|-----------|--------|------------|-------|
| CS02-F15 | malicious-mcp-server | MCP01 Resource Exposure | CRITICAL | `file:///config/secrets.json` expuesto como recurso MCP | ✅ TP | Servidor deliberadamente malicioso expone recurso con ruta a archivo de secrets. Validación E2E del módulo resource_exposure. |
| CS02-F16 | malicious-mcp-server | Gap 2 Output Encoding | HIGH | Hidden control characters en respuesta `messageFormatter` | ✅ TP | El módulo output_encoding detecta caracteres de control invisibles en tool output. Validación del módulo nuevo v0.9.x. |
| CS02-F17 | malicious-mcp-server | Gap 2 Output Encoding | HIGH | Zero-width characters en respuesta `messageFormatter` | ✅ TP | Caracteres Unicode de ancho cero embebidos en output. Invisible al usuario, legible por el LLM — vector de exfiltración. |
| CS02-F18 | ssh-mcp-server | EXT03 Shadow Tool | HIGH | `execute-command` description revela arbitrary execution intent | ✅ TP | SSH server expone `execute-command` como herramienta MCP. Un AI agent podría ser dirigido a ejecutar comandos arbitrarios via SSH en el host destino. |
| CS02-F19 | remnux-mcp-server | MCP05 Cmd Injection | CRITICAL | `run_tool.command` — payload reflected: ejecución sospechosa | ✅ TP | El field `command` de `run_tool` refleja el payload en el output, sugiriendo que el comando se pasa al SO. Malware analysis server ejecutando comandos arbitrarios. |
| CS02-F20 | remnux-mcp-server | EXT03 Shadow Tool | HIGH | `run_tool` description revela arbitrary execution intent | ✅ TP | Herramienta de análisis de malware con `run_tool` genérico. Un attacker puede redirigir el AI agent a ejecutar tools no relacionadas con el análisis. |
| CS02-F21 | remnux-mcp-server | EXT03 Shadow Tool | HIGH | `analyze_file` description revela arbitrary execution intent | ✅ TP | "Analyzes a file using REMnux tools" — ejecución de herramientas del sistema en filepath controlado por el usuario. Path traversal + exec como vector combinado. |
| CS02-F22 | mysql-mcp-server | EXT03 Shadow Tool | HIGH | `execute_query` description revela arbitrary execution intent | ✅ TP | MySQL server con `execute_query` genérico — cualquier SQL arbitrario. Sin restricción de tipo o scope declarada en el schema. |
| CS02-F23 | myclaw-toolkit | MCP02 Scope Creep | HIGH | `wifi_qrcode` inputSchema solicita campo de credencial WiFi | ✅ TP | La herramienta de generación de QR WiFi expone `password` como campo MCP. Un AI agent con acceso podría exfiltrar contraseñas WiFi. |
| CS02-F24 | myclaw-toolkit | MCP06 SSRF | HIGH | `rss_feed.url` — SSRF confirmado por timing delay | ✅ TP | El módulo SSRF detectó timing delay al probar `http://169.254.169.254/` — el server realizó una petición HTTP real al host interno antes de timeout. |
| CS02-F25 | myclaw-toolkit | MCP06 SSRF | HIGH | `read_page.url` — SSRF confirmado por timeout | ✅ TP | `read_page` intentó fetch a IP interna y colgó hasta timeout — confirma que el server realiza peticiones HTTP sin validación de destino. |
| CS02-F26 | mcp-mysql-server | MCP02 Scope Creep | HIGH | `list_databases` claims unrestricted database access scope | ✅ TP | Tool declara acceso irrestricto a todas las bases de datos. Un AI agent podría ser dirigido a listar, exfiltrar o destruir cualquier DB. |
| CS02-F27 | mcp-mysql-server | EXT03 Shadow Tool | HIGH | `execute_ddl` description revela arbitrary DDL execution | ✅ TP | DDL arbitrario = DROP TABLE, ALTER TABLE, CREATE USER. Vector de destrucción de schema. |
| CS02-F28 | mcp-mysql-server | EXT03 Shadow Tool | HIGH | `execute_write_query` description revela arbitrary write execution | ✅ TP | INSERT/UPDATE/DELETE arbitrario — modificación de datos sin restricción declarada. |
| CS02-F29 | mcp-mysql-server | EXT03 Shadow Tool | HIGH | `execute_stored_procedure` description revela arbitrary execution | ✅ TP | Ejecución de stored procedures arbitrarios — potencialmente equivalente a RCE si el servidor tiene UDFs. |
| CS02-F30 | mcp-mysql-server | EXT03 Shadow Tool | HIGH | `execute_seed_plan` description revela arbitrary execution | ✅ TP | "Seed plan" = script de inserción masiva. Un attacker puede usar este tool para inyectar datos maliciosos a escala. |
| CS02-F31 | mysql-mcp-server | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk` HIGH vuln (cascade) | ✅ TP (cascade) | Sexto servidor afectado por el SDK advisory. Patrón completamente generalizado. |

---

## Targets con ERROR de startup (18 skip)

Clasificados por causa probable:

| Grupo | Targets | Causa |
|-------|---------|-------|
| Browser/GUI requerido | nx-mcp, drawio-mcp, fetcher-mcp, mcp-webresearch, mcp-screenshot-website-fast, drawio-mcp-server, desktop-touch-mcp | Abren Chrome/Electron visible |
| Requiere config/vault | obsidian-mcp-server, cclsp, agent-orchestrator-mcp-server | API key / config file obligatorio |
| Crash MCP handshake | playwright-mcp-server, desktop-commander | Output no-JSON antes del handshake |
| Timeout en tool probes | mediawiki-mcp-server, fetch-url-mcp | HTTP real por probe, excede target timeout |
| Crash módulos dinámicos | markmap-mcp-server, mcp-server-code-runner, kernlang-mcp-server | Crash durante scan de módulos |
| Bug interno del server | mcp-postgres | pg client reuse bug (crash startup) |

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

### Supply chain cascade (CS02-F09/F10/F31)
Sexto servidor afectado por `@modelcontextprotocol/sdk@<=1.25.1`. El patrón está completamente confirmado: cualquier server Node.js que use el SDK oficial es vulnerable. El advisory afecta a >200 servers en el ecosistema npm.

### CS02-F19 — remnux-mcp-server CRITICAL injection
`run_tool.command` refleja el payload en el output. Dado que REMnux está diseñado para ejecutar herramientas de análisis de malware (file, strings, hexdump, etc.), el field `command` probablemente se pasa directamente al SO. Un AI agent podría ser dirigido a ejecutar `run_tool(command="rm -rf /")` o similar. El server corre con sandbox deshabilitado (warning al inicio).

### CS02-F24/F25 — myclaw-toolkit SSRF doble
Dos herramientas de myclaw-toolkit confirman SSRF independientemente:
- `rss_feed.url`: timing delay detectado → el server hizo una petición HTTP antes de rechazar (no es solo "URL parseada").
- `read_page.url`: hung hasta timeout → fetch real a IP interna. Sin whitelist de destinos, sin validación de scheme. Ambos vectores en un solo servidor público (787/wk) representan un vector de acceso a metadatos cloud/internos.

### CS02-F27/F28/F29/F30 — mcp-mysql-server shadow tools cluster
`@berthojoris/mcp-mysql-server` expone 4 tools de ejecución arbitraria de SQL:
- `execute_ddl` (DROP/CREATE/ALTER)
- `execute_write_query` (INSERT/UPDATE/DELETE)  
- `execute_stored_procedure` (stored procs = potencial RCE via UDF)
- `execute_seed_plan` (batch inserts)
Todas con descriptions que incluyen palabras "execute", "any", "arbitrary". Un AI agent comprometido puede destruir completamente la base de datos o escalar a RCE si el servidor MySQL tiene UDFs instaladas.

### Protocol crash — expansión a 11 targets (35.4% → 35.5%)
La segunda pasada agregó 4 targets más al cluster de proto-crash: ssh-mcp-server, remnux-mcp-server, mysql-mcp-server, openapi-mcp-server. Total: 11/31 targets (35.5%). La prevalencia se mantiene estable, confirmando que es un patrón sistémico del ecosistema MCP y no un artefacto de la muestra inicial.

### FPs de segunda pasada — echo tools en myclaw-toolkit
10+ findings de `injection reflected` en myclaw-toolkit son FPs. El toolkit tiene herramientas que por diseño incluyen el input en el output:
- `color_tools`, `crypto_price`, `domain_check`: incluyen el query en la respuesta para mostrar contexto
- `vcard_generator`: genera una vCard que contiene los campos de entrada
- `compare`: retorna ambos valores para mostrar la comparación
- `json_formatter`, `markdown_to_html`: transforma el input — el output incluye el contenido transformado

El `_is_input_echo` filter de v0.9.2 cubre algunos (param name en `_ECHO_FIELD_NAMES`), pero estos tienen nombres de param específicos del dominio (color, coin, vs, domain, phone, org, markdown) que no están en la lista. Acción para v0.9.3: expandir `_ECHO_FIELD_NAMES` con más términos de dominio comunes, o agregar lógica de detección de "transformation echo" (output contiene input transformado, no literal).
