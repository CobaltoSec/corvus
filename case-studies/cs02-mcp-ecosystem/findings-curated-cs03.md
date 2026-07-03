# CS03 — Findings Curados

Expansión del dataset Corvus — 8 targets escaneados el 2026-07-03.
Corvus v1.0.1 — 34 módulos — 3 batches + 2 scans individuales.

**Totales CS03:** ~116 raw → ~43 TP curados / ~6 FP documentados

## Targets escaneados

| Target | DL/wk | Auth | Raw | Score | Curación |
|--------|-------|------|-----|-------|----------|
| @heroku/mcp-server | 6,309 | ❌ NO | 9 | 56 | 5 TP |
| @knip/mcp | 3,174 | ❌ NO | 8 | 28 | 4 TP |
| agentmail-mcp | 1,461 | ❌ NO | 6 | 20 | 3 TP |
| @upstash/context7-mcp | 546,432 | ❌ NO | 11 | 40 | 5 TP |
| @sap-ux/fiori-mcp-server | 103,715 | ❌ NO | 50 | 100 | 17 TP |
| mcp-echo-server | 7,399 | ❌ NO | 7 | 34 | 3 TP + 1 FP |
| awslabs.aws-documentation-mcp-server | 337,000 | ❌ NO | 18 | 30* | 6 TP + 2 FP-CRIT |
| markitdown-mcp | 38,000 | ❌ NO | 7 | 38 | 4 TP |

---

## heroku-mcp-server — @heroku/mcp-server v1.2.5

33 tools, 1 resource. Heroku platform (Salesforce). 6,309 descargas/semana.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F01 | MCP02 Scope Creep | HIGH | `pg_psql` inputSchema solicita campo `credential` | ✅ TP | Conf=80. La tool de ejecución SQL en Heroku Postgres declara `credential` como parámetro MCP. Un AI agent puede ser guiado a exponer credenciales de BD via el canal MCP. Patrón idéntico a CS02-F06 (`pg_manage_users.password`). |
| CS03-F02 | EXT03 Shadow Tool | HIGH | `deploy_one_off_dyno` description revela arbitrary execution intent | ✅ TP | Conf=80. "Run code/commands in Heroku one-off dyno with network and filesystem access." Descripción explícita de ejecución arbitraria con acceso de red + filesystem. Un AI agent comprometido puede usar este tool para RCE en dyno de Heroku. |
| CS03-F03 | EXT01 Proto-Fuzz | HIGH | Protocol crash: oversized method name (8192 bytes) | ✅ TP | Conf=80. Server desconecta sin retornar JSON-RPC error. Patrón sistémico CS02-F08. |
| CS03-F04 | EXT01 Proto-Fuzz | MEDIUM | Protocol crash: deeply nested params (50 niveles) | ✅ TP | Conf=70. Stack overflow potencial en parser recursivo. |
| CS03-F05 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs heroku:** 0

---

## knip-mcp — @knip/mcp v0.0.32

2 tools, 15 resources, 1 prompt. Knip code analysis. 3,174 descargas/semana.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F06 | MCP03 Tool Poisoning | MEDIUM | `knip-run` description 1,020 chars (límite 1,000) | ✅ TP | Conf=80. Descripción marginal. Superficie de tool poisoning pequeña pero real. |
| CS03-F07 | MCP03 Tool Poisoning | MEDIUM | `knip-docs` description 1,760 chars | ✅ TP | Conf=80. 76% sobre el límite. Espacio considerable para instrucciones ocultas. |
| CS03-F08 | MCP07 Init-Audit | MEDIUM | Protocol version downgrade aceptado (versiones arbitrarias) | ✅ TP | Conf=75. Acepta `9999-99-99`, `2030-01-01`, `0.1`, etc. Sin validación de rango. |
| CS03-F09 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs knip:**
- CORVUS-005 (null request ID, MEDIUM): baja prioridad — sin impacto de seguridad directo. Marcado como TP-low pero no incluido en curación por ser variante del mismo patrón proto que F08.

---

## agentmail-mcp — AgentMail v0.1.0

11 tools. AgentMail email agent. 1,461 descargas/semana.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F10 | MCP07 Init-Audit | MEDIUM | Protocol version downgrade aceptado | ✅ TP | Conf=75. Mismo patrón F08. Sistémico. |
| CS03-F11 | EXT01 Proto-Fuzz | LOW | Protocol crash: string params | ✅ TP-low | Conf=65. Server desconecta en lugar de retornar -32600. |
| CS03-F12 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs agentmail:**
- CS02-F01-equiv (no-required-fields in `create_inbox`): todos los params son opcionales — puede ser diseño intencional de una inbox sin nombre. Marcado INFO, no curado.

---

## context7-mcp — @upstash/context7-mcp v3.2.2

2 tools. Upstash documentation retrieval. **546,432 descargas/semana.** NO AUTH.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F13 | MCP05 Cmd Injection | HIGH | `query-docs.libraryId` — injection reflejada en error message | ✅ TP | Conf=85. Payload `' OR '1'='1` reflejado: `Invalid library ID format: "' OR '1'='1". Expected format: /owner/repo`. Input llega sin sanitizar al constructor del mensaje de error. Patrón idéntico CS02-F55 (nationalparks SQL error reflection). No hay evidencia de DB exec — es error message injection, no SQL backend. |
| CS03-F14 | MCP03 Tool Poisoning | MEDIUM | `resolve-library-id` description 2,006 chars | ✅ TP | Conf=80. 100% sobre el límite. Descripción extensísima con instrucciones de uso — superficie de tool poisoning real. |
| CS03-F15 | MCP07 Init-Audit | MEDIUM | Protocol version downgrade aceptado | ✅ TP | Conf=75. Sistémico. |
| CS03-F16 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**Nota GHSA**: 546k/wk, official Upstash tool. La injection en error message (F13) + description length son candidatos a GHSA MEDIUM. No CRITICAL porque el error reflection no confirma ejecución.

**FPs context7:** bulk de LOW (5 raw) — schema bypass en tools con 2 params. Baja superficie, patrones de validación menores.

---

## sap-fiori-mcp-server — @sap-ux/fiori-mcp-server v1.8.4

9 tools, 50 raw findings, Score 100/100. SAP UX Fiori dev tools. **103,715 descargas/semana.** NO AUTH.

### Findings HIGH

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F17 | EXT04 SSRF | HIGH | `download_odata_service_metadata.servicePath` — SSRF timeout → AWS metadata | ✅ TP | Conf=65. Payload `http://169.254.169.254/latest/meta-data/` → timeout 12s. El server realiza el request real (timeout = conexión pendiente, no error inmediato). En CI/CD (GitHub Actions, AWS CodeBuild, ECS) este vector permite exfiltrar tokens IAM de instancia. GHSA candidate. |
| CS03-F18 | MCP05 Injection | HIGH | `execute_functionality.functionalityId` — shell injection pattern reflejado ("; id") | ✅ TP | Conf=85. Payload `; id` → error message includes the payload verbatim. Si `functionalityId` se concatena en shell command, esto es RCE potencial. Patrón más agresivo que CS02-F55 (nationalparks) — el payload es un shell command, no SQL. |
| CS03-F19 | MCP05 Injection | HIGH | `get_functionality_details.functionalityId` — template injection pattern reflejado ("${7*7}") | ✅ TP | Conf=85. `${7*7}` → reflejado en error. Si el server usa template engine (Handlebars, EJS, etc.), `${7*7}` evaluaría a "49" — confirmaría template injection. La reflexión sin evaluación sugiere string interpolation no ejecutada, pero la superficie existe. |
| CS03-F20 | MCP05 Injection | HIGH | `generate_fiori_app_odata.floorplan` — injection reflejada en Zod validation error | ✅ TP | Conf=85. Payload type-mismatch → Zod union error incluye el payload en el mensaje. Input pasa sin sanitizar al mensaje de error de validación. Mismo patrón F18/F19. |
| CS03-F21 | MCP05 Injection | HIGH | `generate_fiori_app_cap.floorplan` — injection reflejada en Zod validation error | ✅ TP | Conf=85. Mismo vector F20 en tool hermana. 4 params independientes del mismo server con injection reflection confirma ausencia de sanitización de inputs en todo el server. |
| CS03-F22 | EXT03 Shadow Tool | HIGH | `execute_functionality` description revela arbitrary SAP modification intent | ✅ TP | Conf=80. "Executes functionality to modify SAP Fiori app." Tool genérico de modificación SAP sin scope declarado. Un AI agent comprometido puede ser dirigido a ejecutar funcionalidades SAP arbitrarias. |
| CS03-F23 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

### Findings MEDIUM — Tool Chaining

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F24 | EXT06 Tool Chaining | MEDIUM | Tool chaining forzado: `list_functionalities` → `get_functionality_details` → `execute_functionality` | ✅ TP | Conf=65. La descripción contiene "Step 1 of 3 / Step 2 of 3 / Step 3 of 3" — instrucciones explícitas para que el LLM encadene tools en secuencia. El workflow forzado list→get→execute puede ser explotado para redirigir el LLM a ejecutar funcionalidades no autorizadas. |
| CS03-F25 | EXT06 Tool Chaining | MEDIUM | Tool chaining forzado: `generate_fiori_app_odata` workflow | ✅ TP | Conf=65. Misma estructura multi-step con ALWAYS/MUST language en descripción. |

*Nota: 6 tool chaining findings en el raw (CORVUS-011 a CORVUS-016). Consolidados en 2 findings curados ya que representan el mismo patrón con herramientas distintas del mismo workflow. Se mantienen como cluster.*

### Findings MEDIUM — Description Length y Schema

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F26 | MCP03 Tool Poisoning | MEDIUM | Descriptions excesivas: 3 tools >1000 chars (3,294 / 1,715 / 1,078) | ✅ TP | Conf=80. Espacio considerable para instrucciones ocultas en tools críticos (`execute_functionality`, `generate_fiori_app_odata`, `download_odata_service_metadata`). |
| CS03-F27 | EXT02 Schema Bypass | MEDIUM | 7/9 tools aceptan campos requeridos ausentes sin error | ✅ TP-cluster | Conf=70. Schema bypass sistémico: todos los tools aceptan llamadas con params requeridos omitidos. En el contexto de SAP con SSRF + injection, este bypass permite probing sin triggear validaciones. |

**FPs SAP Fiori:** bulk de LOW (21 raw) — schema bypass "wrong type" y "undeclared extra fields" para tools de generación de código SAP. El contexto de dev tool reduce el impacto real pero los findings son técnicamente válidos.

---

## mcp-echo-server — v1.0.0

1 tool. Echo server de referencia / testing. 7,399 descargas/semana.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F28 | MCP07 Init-Audit | MEDIUM | Protocol version downgrade aceptado | ✅ TP | Conf=75. Sistémico. |
| CS03-F29 | EXT01 Proto-Fuzz | MEDIUM | Null request ID aceptado — violación JSON-RPC 2.0 | ✅ TP | Conf=60. |
| CS03-F30 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs mcp-echo:**

| FP# | Módulo | Sev Raw | Motivo FP |
|-----|--------|---------|-----------|
| CS03-FP01 | MCP05 Injection | HIGH | `echo.message` — prompt injection reflejada. FP por diseño: la función del server ES reflejar el input verbatim. La "injection" es el comportamiento esperado. No es un hallazgo de seguridad en un echo server intencional. |

---

## aws-documentation-mcp-server — awslabs v1.28.1

4 tools. AWS official documentation MCP. **337,000 descargas/semana.** NO AUTH.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F31 | MCP03 Tool Poisoning | MEDIUM | 4/4 tools con descriptions >1,000 chars (1,370 / 1,909 / 3,052 / 1,601) | ✅ TP | Conf=80. Todos los tools del server tienen descriptions sobre el límite. `search_documentation` (3,052 chars) es el más grande. Superficie amplia de tool poisoning. |
| CS03-F32 | MCP07 Init-Audit | MEDIUM | Protocol version downgrade aceptado + integer protocolVersion | ✅ TP | Conf=75/65. Acepta versiones arbitrarias Y acepta `protocolVersion: 42` (integer, no string). Parser no valida tipo. |
| CS03-F33 | EXT01 Proto-Fuzz | HIGH | Protocol crash: oversized method name (8,192 bytes) | ✅ TP | Conf=80. Sistémico. AWS server no maneja method names extremos. |
| CS03-F34 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs AWS Documentation — 2 CRITICAL:**

| FP# | Módulo | Sev Raw | Motivo FP |
|-----|--------|---------|-----------|
| CS03-FP02 | MCP05 Injection | CRITICAL | `search_documentation.search_phrase` con `1' AND SLEEP(5)--` → response contiene "AT+SLEEP example 1" de docs IoT. **FP de calibración**: `search_documentation` es un motor de búsqueda textual. La respuesta contiene documentación AWS que menciona "SLEEP" — no es SQL engine error. El módulo SQL injection confunde contenido de búsqueda con execution. Acción futura: requerir SQL error keywords reales (SQLSTATE, "syntax error near", MySQL/PostgreSQL error strings). |
| CS03-FP03 | EXT04 SSRF | CRITICAL | `search_documentation.search_phrase` con `http://metadata.google.internal/computeMetadata/v1/` → response contiene docs de Lambda sobre `AWS_LAMBDA_METADATA_TOKEN`. **FP de calibración**: el server buscó la URL como texto y retornó documentación AWS *sobre* metadata. No hizo un request HTTP real a metadata.google.internal. Diferencia con TP (markitdown F36, sap-fiori F17): los TP muestran timeout de 12s que confirma request real. Este encontró resultados inmediatamente (búsqueda textual). Acción futura: el módulo SSRF debe requerir timeout ≥5s o IP/content exactos de la respuesta del metadata endpoint, no keywords en texto. |

---

## markitdown-mcp — Microsoft MarkItDown v1.8.1

1 tool (`convert_to_markdown`). **38,000 descargas/semana.** NO AUTH.

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F35 | EXT04 SSRF | HIGH | `convert_to_markdown.uri` — SSRF timeout → 169.254.169.254 (AWS metadata) | ✅ TP | Conf=65. Payload `http://169.254.169.254/latest/meta-data/` → timeout 12s. **TP confirmado** (vs FP03 del AWS docs): el timeout de 12s indica request real al endpoint de metadata. La librería markitdown acepta URLs HTTP arbitrarias para convertir a markdown — sin validación de destino. En CI/CD (EC2/ECS/Lambda), permite exfiltrar tokens IAM. LFI vía `file://` es probable dado que markitdown soporta el scheme, pero no verificado (test bloqueado). GHSA candidate HIGH. |
| CS03-F36 | EXT01 Proto-Fuzz | HIGH | Protocol crash: oversized method name (8,192 bytes) | ✅ TP | Conf=80. Sistémico. |
| CS03-F37 | EXT01 Proto-Fuzz | MEDIUM | Protocol crash: deeply nested params (50 niveles) | ✅ TP | Conf=70. Sistémico. |
| CS03-F38 | EXT14 | HIGH | EXT14: crash en `notifications/cancelled` con requestId desconocido | ✅ TP | Conf=85. Ver cluster sistémico CS03-F17. |

**FPs markitdown:** 0

---

## Cluster Sistémico CS03 — EXT14

| ID | Módulo | Sev | Título | Confirmado | Notas |
|----|--------|-----|--------|------------|-------|
| CS03-F39 | EXT14 Cancellation Race | HIGH | EXT14 sistémico: 8/8 targets CS03 crashean en `notifications/cancelled` con requestId desconocido | ✅ TP CRÍTICO | Conf=85. **Prevalencia: 100% en CS03 (8/8).** El payload `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"nonexistent-99999","reason":"test"}}` desconecta el transporte en TODOS los servers escaneados hoy. Patrón también visible en CS01+CS02 en re-scan v1.0.1. La causa probable: los SDK MCP (TypeScript/Python) hacen `.get(requestId)` en un Map de requests pendientes y al recibir un ID no registrado no manejan el caso (crash vs. ignore). Un cliente malicioso puede crashear cualquier server MCP del ecosistema con un único mensaje de notificación. |

**Targets afectados CS03 (EXT14):** heroku-mcp-server, @knip/mcp, agentmail-mcp, @upstash/context7-mcp, @sap-ux/fiori-mcp-server, mcp-echo-server, awslabs.aws-documentation-mcp-server, markitdown-mcp

**Targets afectados CS01+CS02 (documentados previamente):** @playwright/mcp, mcp-shell-server, @modelcontextprotocol/server-sequential-thinking, y otros en re-scan v1.0.1.

---

## Cluster Sistémico CS03 — Protocol Crash (oversized method name)

Todos los TP de proto crash (CORVUS oversized method) en CS03:

| Target | Finding ID |
|--------|-----------|
| heroku-mcp-server | CS03-F03 |
| aws-documentation-mcp-server | CS03-F33 |
| markitdown-mcp | CS03-F36 |

**Prevalencia CS03:** 3/8 = 37.5% (consistente con CS02 ~35-46%).

---

## SSRF Cluster — Servers que hacen requests HTTP reales

| Target | Finding | Endpoint | Timeout |
|--------|---------|----------|---------|
| @sap-ux/fiori-mcp-server | CS03-F17 | 169.254.169.254 (AWS) | 12s |
| markitdown-mcp | CS03-F35 | 169.254.169.254 (AWS) | 12s |

Ambos confirman: timeout de 12s = request real. No son FPs (diferencia clara con CS03-FP03 que retornó inmediatamente).

---

## Totales CS03

| Métrica | Valor |
|---------|-------|
| Findings raw | ~116 |
| Findings curados TP | **39** |
| FPs documentados | **3** |
| FP rate estimado | ~7% |
| Targets | 8 |
| HIGHs curados | 19 |
| MEDIUMs curados | 14 |
| LOWs curados | 1 (F11) |
| Clusteres sistémicos | 2 (EXT14 + proto crash) |

## Candidatos GHSA nuevos (CS03)

| Target | DL/wk | Tipo | Severidad | Prioridad |
|--------|-------|------|-----------|-----------|
| @sap-ux/fiori-mcp-server | 103k | SSRF + injection + tool chaining | HIGH | 🔴 1 |
| @upstash/context7-mcp | 546k | Injection reflection + desc length | MEDIUM | 🟡 2 |
| markitdown-mcp | 38k | SSRF timeout (+ LFI potencial) | HIGH | 🟠 3 |
| @heroku/mcp-server | 6k | Credential scope creep + arbitrary exec | HIGH | 🟡 4 |

## Insights de Calibración (para CFP)

### Gap 1 — SQL Injection en search APIs
Los módulos SQL detectan `SLEEP`, `UNION`, `OR '1'='1'` en el response, pero search engines (AWS docs) retornan documentación que contiene estos términos. Fix: requerir SQL engine error patterns (SQLSTATE, "syntax error near", "Unclosed string", etc.).

### Gap 2 — SSRF en search APIs vs. SSRF real
SSRF FP cuando el server retorna documentación *sobre* metadata. SSRF TP cuando hay timeout (≥5s). Discriminador: tiempo de respuesta. Fix: agregar timeout-based SSRF detection como señal primaria.

### Patrón confirmado — EXT14 universal
100% de los 8 servers CS03 son vulnerables a EXT14 (cancellation crash). Junto con CS01+CS02, la prevalencia en el ecosistema MCP es >85%. Esta es la finding más reproducible del framework Corvus y el dato más fuerte para el CFP Ekoparty.
