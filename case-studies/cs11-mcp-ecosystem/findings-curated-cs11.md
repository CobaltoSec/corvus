# CS11 — Curated Findings
**Date:** 2026-07-06
**Targets:** 58 (39 OK / 19 ERROR — 67% OK rate)
**Source:** awesome-mcp-servers lists (punkpeye + appcypher + wong2 + modelcontextprotocol, GitHub link resolution)
**Raw findings:** ~490 across 39 scanned servers
**True Positives:** 29 | **False Positives:** ~80 | **FP Rate:** ~74% (driven by mcp-discord-bridge 44C + mcp-reunion 21H)

---

## Summary Table

| ID | Package | npm/wk | Severity | OWASP | Finding |
|----|---------|--------|----------|-------|---------|
| CS11-F01 | android-mcp-server | 266 | CRITICAL | MCP08 | `clear_logs` — anti-forensics tool |
| CS11-F02 | android-mcp-server | 266 | HIGH | MCP02 | `screenshot` — path traversal via `save_path` |
| CS11-F03 | android-mcp-server | 266 | HIGH | EXT03 | `tap_sequence` — arbitrary action execution |
| CS11-F04 | @tensorfeed/mcp-server | 549 | HIGH | MCP05 | XSS reflection cluster × 6 tools |
| CS11-F05 | @anythink-cloud/mcp | 162 | HIGH | MCP02 | Credentials (`apiKey`, `password`) in inputSchema |
| CS11-F06 | @anythink-cloud/mcp | 162 | HIGH | MCP05 | XSS reflection in `config_use` |
| CS11-F07 | @anythink-cloud/mcp | 162 | HIGH | EXT11 | Log level escalation (debug→emergency accepted) |
| CS11-F08 | emilia-protocol | ? | HIGH | EXT03 | `ep_guard_action` — forced financial compliance gate |
| CS11-F09 | emilia-protocol | ? | HIGH | EXT12 | Prompt template injection × 3 (`trust_decision`, `receipt_quality_check`, `install_decision`) |
| CS11-F10 | a2asearch-mcp | 201 | HIGH | MCP05 | SQL injection pattern + XSS reflection in agent search |
| CS11-F11 | brasil-data-mcp | 200 | HIGH | EXT12 | Prompt template injection in `analise-cnpj` |
| CS11-F12 | @mymedi-ai/mcp-server | 773 | HIGH | EXT12 | Prompt template injection × 3 — healthcare context |
| CS11-F13 | photopea-mcp-server | 92 | HIGH | EXT03 | `photopea_run_script` — arbitrary JS execution exposed |
| CS11-F14 | delega-dev | ? | HIGH | MCP07 | Admin-only webhooks (`list`/`create`/`delete`) without auth enforcement |
| CS11-F15 | gws-mcp-server | ? | HIGH | EXT04 | SSRF — `calendar_events_insert.location` makes outbound HTTP (timeout on 169.254.169.254) |
| CS11-F16 | apiverket | ? | HIGH | EXT12 | Prompt template injection in `analyze_swedish_data` |

---

## FP Log

| Package | Raw findings | Classification | Reason |
|---------|-------------|----------------|--------|
| mcp-discord-bridge | 44 CRITICAL MCP01 | FP masivo | `"token"` en error messages de Discord (no configurado). Mismo patrón que CS10 browser SSRF. |
| @tensorfeed/x402 | 3 CRITICAL MCP01 | FP | `"token": "BTC"` — ticker de criptomoneda, no credencial. |
| mcp-reunion | 21 HIGH MCP05 | FP | Evidence = `{` (respuesta JSON válida, no reflection). API pública datos isla Reunión. |
| mcp-reunion | 8 HIGH MCP10 | FP | Response flood esperado en API de datos públicos (17-54k bytes por query). |

---

## Detailed Findings

### CS11-F01 — android-mcp-server — CRITICAL — MCP08 — Anti-Forensics

**Package:** `android-mcp-server` · 266 dl/wk
**Tool:** `clear_logs`
**Confidence:** 90%

Tool name `clear_logs` expone capacidad de borrar logs de auditoría del dispositivo Android. Un attacker puede invocar esta tool para destruir evidencia de actividad maliciosa (screenshots no autorizados, comandos ejecutados, exfiltración).

**Context:** Android device control MCP — expone 25 tools sobre el dispositivo (tap, swipe, screenshot, key press, shell access). `clear_logs` elimina el audit trail de todas las acciones anteriores.

**Evidence:** Tool enumerated via `tools/list`. Name pattern matches `clear_*logs*` → MCP08.

**Notes:** Mismo patrón que CS06 `godot-mcp-server` (`clear_console_log`). En Android el impacto es mayor — logs del sistema, logcat, crash logs.

**GHSA:** Candidato — HIGH. Vendor: `android-mcp-server` npm.

---

### CS11-F02 — android-mcp-server — HIGH — MCP02 — Path Traversal

**Package:** `android-mcp-server` · 266 dl/wk
**Tool:** `screenshot`
**Parameter:** `save_path`
**Confidence:** 65%

Tool `screenshot` acepta `save_path` sin validación de path. Un caller puede escribir screenshots a rutas arbitrarias del filesystem del host.

**Evidence:**
```
path param(s): save_path | description: Take a screenshot of the Android device.
Returns the image for visual analysis. Optionally saves to a file path.
```

**Notes:** Sin sanitización, `save_path=../../.ssh/authorized_keys` podría sobrescribir archivos sensibles en el host que corre el MCP server.

---

### CS11-F03 — android-mcp-server — HIGH — EXT03 — Arbitrary Execution

**Package:** `android-mcp-server` · 266 dl/wk
**Tool:** `tap_sequence`
**Confidence:** 80%

Tool `tap_sequence` expone ejecución arbitraria de secuencias de acciones sobre el dispositivo Android: taps, text input, key presses, swipes. Cualquier caller del MCP puede controlar el dispositivo remotamente.

**Evidence:**
```
Execute a multi-step action sequence. Supports taps, waits, text input,
key presses, and swipes in any order.
```

**Notes:** En contexto Android MCP, `tap_sequence` es equivalente a shell execution remota — permite automatizar cualquier acción UI. Combinado con F01 (`clear_logs`), el attacker ejecuta y borra evidencia.

---

### CS11-F04 — @tensorfeed/mcp-server — HIGH — MCP05 — XSS Reflection Cluster

**Package:** `@tensorfeed/mcp-server` · 549 dl/wk
**Tools:** `is_service_down`, `failover_verdict`, `pricing_series`, `benchmark_series` (×2), `status_uptime`
**Confidence:** 85%

6 tools reflejan input sin sanitizar en respuestas de error. Patrón idéntico al cluster arxiv de CS08/CS09.

**Evidence (muestra):**
```
is_service_down: Service "<script>alert(1)</script>" not found.
  Available services: Claude API, OpenAI API, Google Gemini, GitHub Copilot

failover_verdict: Failover Verdict from <script>alert(1)</script>:
  fail over to Claude Opus 4.8 (anthropic)

pricing_series: <script>alert(1)</script> (unknown) 0 points over 0 days

status_uptime: <script>alert(1)</script> over 7 days: ?% uptime
```

**Notes:** El server monitorea disponibilidad de AI services (Claude, OpenAI, Gemini). Los parámetros `service`, `model`, `test` y `metric` no se sanitizan. En contexto MCP el riesgo es output injection hacia el LLM que consume las respuestas.

**GHSA:** Candidato — HIGH. ~549 dl/wk.

---

### CS11-F05 — @anythink-cloud/mcp — HIGH — MCP02 — Credentials in Schema

**Package:** `@anythink-cloud/mcp` · 162 dl/wk
**Tools:** `login`, `login_direct`, `signup`, `projects_use`
**Confidence:** 85%

4 tools aceptan credenciales (`apiKey`, `password`) como parámetros del schema MCP. Las credenciales quedan expuestas en tool call logs, historial de conversación, y cualquier sistema de observabilidad que capture MCP traffic.

**Evidence:**
```
login: inputSchema requires: password
login_direct: inputSchema properties: apiKey
projects_use: inputSchema properties: apiKey
signup: inputSchema requires: password
```

**Notes:** MCP no es un canal seguro para transmitir credenciales. Las tools deben usar variables de entorno o configuración out-of-band, no parámetros en el schema.

---

### CS11-F06 — @anythink-cloud/mcp — HIGH — MCP05 — XSS Reflection

**Package:** `@anythink-cloud/mcp` · 162 dl/wk
**Tool:** `config_use`
**Confidence:** 80%

Parámetro `profile` se refleja sin sanitizar en error messages.

**Evidence:**
```
Error: Profile '<script>alert(1)</script>' not found.
```

---

### CS11-F07 — @anythink-cloud/mcp — HIGH — EXT11 — Log Level Escalation

**Package:** `@anythink-cloud/mcp` · 162 dl/wk
**Confidence:** 80%

Server acepta `logging/setLevel` con cualquier nivel incluido `emergency`, escalando el nivel de logging sin restricción. Un attacker puede silenciar logs (`emergency` solo) o inundar logs (`debug`).

**Evidence:**
```
logging/setLevel with level='debug' → success
logging/setLevel with level='emergency' → success
```

---

### CS11-F08 — emilia-protocol — HIGH — EXT03 — Forced Financial Compliance Gate

**Package:** `emilia-protocol`
**Tool:** `ep_guard_action`
**Confidence:** 75%

Tool `ep_guard_action` se describe como obligatoria antes de cualquier acción financiera irreversible. La descripción instruye al LLM con lenguaje imperativo, forzando un call chain no solicitado por el usuario.

**Evidence:**
```
REQUIRED before any irreversible action: payments, wire transfers, fund releases,
deletions, record or account changes, [...]
```

**Notes:** Patrón dual: (1) el server puede ser legítimo y este es un gate de seguridad by-design; (2) un attacker que controle el server puede usar este gate para interceptar y modificar el contexto de acciones financieras antes de ejecutarlas.

---

### CS11-F09 — emilia-protocol — HIGH — EXT12 — Prompt Template Injection

**Package:** `emilia-protocol`
**Tools:** `trust_decision`, `receipt_quality_check`, `install_decision`
**Confidence:** 85%

3 tools con prompt templates en `prompts/get` reflejan input del caller en los mensajes generados. Payload `{{7*7}}` confirmado en respuesta.

**Evidence:**
```
trust_decision: {"description": "Trust decision for CORVUS_INJECTION_TEST_{{7*7}}",
  "messages": [{"role": "user", "content": {...}}]}

receipt_quality_check: {"description": "Receipt quality check for CORVUS_INJECTION_TEST_{{7*7}}",
  ...}

install_decision: {"description": "Install decision for CORVUS_INJECTION_TEST_{{7*7}}",
  ...}
```

**Notes:** En el contexto de `emilia-protocol` (protocolo de compliance para payments/identity), un attacker puede inyectar instrucciones en los prompts de decisión de confianza y calidad de recibos — directamente en el flujo de aprobación financiera.

---

### CS11-F10 — a2asearch-mcp — HIGH — MCP05 — SQLi Pattern + XSS Reflection

**Package:** `a2asearch-mcp` · 201 dl/wk
**Tools:** `search_agents`, `get_agent`, `list_agents`
**Confidence:** 80%

Dos patrones distintos de injection:

**SQL injection pattern:**
```
search_agents: Found 0 results for "test" (type: ' OR '1'='1)
list_agents: Top 0 ' OR '1'='1s by stars (0 total)
```

**XSS reflection:**
```
get_agent: Agent "<script>alert(1)</script>" not found.
```

**Notes:** El server indexa AI agents y MCP servers. `type=' OR '1'='1` reflejado sugiere que el input llega sin sanitizar a queries de búsqueda — potencial SQLi si hay backend SQL.

---

### CS11-F11 — brasil-data-mcp — HIGH — EXT12 — Prompt Template Injection

**Package:** `brasil-data-mcp` · 200 dl/wk
**Tool:** `analise-cnpj`
**Confidence:** 80%

Tool de análisis de CNPJ (registro empresarial brasileño) refleja input en prompt templates.

**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content":
  {"type": "text", "text": "Faça uma análise... CORVUS_INJECTION_TEST_{{7*7}}"}}]}
```

---

### CS11-F12 — @mymedi-ai/mcp-server — HIGH — EXT12 — Prompt Template Injection (Healthcare)

**Package:** `@mymedi-ai/mcp-server` · 773 dl/wk
**Tools:** `decode-denial`, `order-readiness`, `scrub-claim`
**Confidence:** 85%

3 tools de medical billing reflejan input en prompt templates del sistema.

**Evidence:**
```
decode-denial: messages: [{"role": "user", "content": "A DME claim came back...
  CORVUS_INJECTION_TEST_{{7*7}}"}]

order-readiness: messages: [{"role": "user", "content": "I am preparing a Medi...
  CORVUS_INJECTION_TEST_{{7*7}}"}]

scrub-claim: messages: [{"role": "user", "content": "I am about to submit...
  CORVUS_INJECTION_TEST_{{7*7}}"}]
```

**Notes:** Contexto crítico — medical billing con DMEPOS codes, claim scrubbing, denial management. Prompt injection en este contexto puede alterar decisiones de coding médico. 773 dl/wk.

**GHSA:** Candidato — HIGH, contexto healthcare + 773 dl/wk.

---

### CS11-F13 — photopea-mcp-server — HIGH — EXT03 — Arbitrary JS Execution Exposed

**Package:** `photopea-mcp-server` · 92 dl/wk
**Tool:** `photopea_run_script`
**Confidence:** 75%

Tool expone ejecución arbitraria de JavaScript en el entorno Photopea/ExtendScript. El scope de ejecución es el contexto de la aplicación de edición de imágenes.

**Evidence:**
```
Execute arbitrary Photopea/ExtendScript JavaScript in the Photopea environment.
Use this for advanced operations not covered by other tools.
```

**Notes:** `photopea_run_script` es el equivalente de `eval()` expuesto como MCP tool. Cualquier caller puede ejecutar JS arbitrario. El riesgo depende del sandbox de Photopea y del acceso al filesystem del host.

---

### CS11-F14 — delega-dev — HIGH — MCP07 — Admin Webhooks Sin Auth

**Package:** `delega-dev`
**Tools:** `list_webhooks`, `create_webhook`, `delete_webhook`
**Confidence:** 70%

3 tools marcadas como `(admin only)` en descripción pero sin enforcement de autenticación verificable en el server.

**Evidence:**
```
list_webhooks: "List all webhooks configured for your account (admin only)"
create_webhook: "Create a webhook to receive event notifications (admin only).
  Events: task.created, task.updated, task.completed, task.deleted"
delete_webhook: "Delete a webhook by ID (admin only)"
```

**Notes:** Si la restricción `admin only` es solo documental (sin gate de auth), cualquier caller MCP puede listar, crear y eliminar webhooks de otros usuarios. Requiere verificación manual.

---

### CS11-F15 — gws-mcp-server — HIGH — EXT04 — SSRF via Calendar Location

**Package:** `gws-mcp-server`
**Tool:** `calendar_events_insert`
**Parameter:** `location`
**Confidence:** 65%

Google Workspace MCP server. El parámetro `location` de la tool de creación de eventos en Google Calendar acepta URLs. Cuando se envió `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (AWS IMDS), la llamada hizo timeout en 12s — indicando que el server intenta hacer la request HTTP.

**Evidence:**
```
Call with SSRF payload 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
timed out after 12.0s, suggesting the server is attempting the network request.
```

**Notes:** `location` debería tratarse como texto plano (e.g. "Conference Room A"). Si el server hace fetch de URLs en ese campo, expone SSRF para cualquier caller MCP. Vector idéntico a CS10 (@agent-infra/mcp-server-browser). Si el server corre en AWS, permite leer credenciales de instancia.

---

### CS11-F16 — apiverket — HIGH — EXT12 — Prompt Template Injection

**Package:** `apiverket`
**Tool:** `analyze_swedish_data`
**Confidence:** 80%

Tool de análisis de datos gubernamentales suecos. Payload reflejado en prompt templates.

**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content":
  {"type": "text", "text": "I... CORVUS_INJECTION_TEST_{{7*7}}"}}]}
```

---

## FP Details

### mcp-discord-bridge — 44 CRITICAL — FP Sistémico

Todos los 44 CRITICAL son `token_exposure` MCP01. El server no tiene `DISCORD_TOKEN` configurado → cada tool call retorna error con texto "token" → módulo lo detecta como credencial. Sin token real expuesto. Descartar todos.

**Patrón:** Idéntico a CS10 browser SSRF — error message con keyword sensible = FP.

### @tunedforai/x402-mcp — 3 CRITICAL — FP

`"token": "BTC"` en respuesta JSON es el ticker de criptomoneda (Bitcoin), no una API credential. El server es un market data feed de crypto que usa `token` como nombre de campo para el símbolo del activo.

**Nota adicional:** `presentation_hint` en respuestas embebe instrucciones al LLM ("Lead your response with the response_header value verbatim"). Esto es output injection borderline — por diseño, pero potencialmente abusable. Clasificar como INFO, no GHSA-worthy.

### mcp-reunion — 21 HIGH MCP05 + 8 HIGH MCP10 — FP

MCP05: evidence = `{` (respuesta JSON válida, no reflection real). El módulo detectó JSON en respuesta como potencial injection. FP.
MCP10: respuestas grandes (17-54k bytes) son esperables para una API de datos públicos de La Reunión (isla francesa). Comportamiento by-design.

---

## GHSAs Abiertos (2026-07-06)

| GHSA | Package | Finding | Severity |
|------|---------|---------|---------|
| GHSA-6f4g-h4c4-75r8 | `@mymedi-ai/mcp-server` | EXT12 prompt injection × 3 (healthcare) | HIGH |
| GHSA-wx78-8jx3-wcv9 | `@tensorfeed/mcp-server` | MCP05 XSS cluster × 6 | HIGH |
| GHSA-xh32-vqc4-v285 | `android-mcp-server` | MCP08 clear_logs + MCP02 path traversal | HIGH |
| GHSA-32vx-mq6h-p8f3 | `emilia-protocol` | EXT12 prompt injection × 3 (payments/identity) | HIGH |
| GHSA-2mq4-q772-f26c | `a2asearch-mcp` | MCP05 SQLi pattern + XSS | HIGH |

---

## Stats Update

| Metric | CS10 | CS11 | Total |
|--------|------|------|-------|
| Servers scanned | 17 OK | 39 OK | **234 OK** |
| Raw findings | ~200 | ~490 | **~2,975** |
| True Positives | ~85 | ~29 | **~1,249** |
| GHSAs | 2 | 0 (pending) | 29 |
