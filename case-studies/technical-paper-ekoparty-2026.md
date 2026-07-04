# Corvus: Auditoría Automatizada de Seguridad del Ecosistema MCP a Escala

**Nicolás Padilla** — CobaltoSec (Argentina)  
**Contacto:** nicolas@cobalto-sec.tech  
**Repositorio:** https://github.com/CobaltoSec/corvus  
**PyPI:** `pip install cobaltosec-corvus` (v1.0.1)  
**Fecha:** Julio 2026

---

## Resumen

El Model Context Protocol (MCP) es el estándar de facto para conectar agentes de IA con herramientas externas, pero su ecosistema público nunca fue auditado sistemáticamente. Presentamos Corvus, un framework de testing de seguridad open source de 34 módulos que mapea al OWASP MCP Top 10. Auditamos 101 servidores MCP reales en cuatro case studies, generando 1.267 findings brutos con 741 verdaderos positivos confirmados. Reportamos 24 security advisories a maintainers incluyendo Microsoft, SAP, Notion y Atlassian. Entre los hallazgos más relevantes: crash universal en el 100% de los servidores con payload de 37 bytes, un vector de C2 encubierto via sampling, y tres nuevos patrones de ataque específicos de la capa agéntica sin documentación pública previa.

---

## 1. Introducción

MCP define el protocolo de comunicación entre AI agents y tool servers. Un servidor MCP expone herramientas (tools), recursos y prompts a cualquier cliente compatible — Claude, GPT-4, Cursor, Copilot, n8n y decenas de plataformas más. A julio 2026, el registro npm contiene más de 2.000 paquetes con prefijo `mcp-*` o sufijo `*-mcp-server`. PyPI suma otro millar. La mayoría se instala sin credenciales vía `npx` o `uvx`.

Esta superficie de ataque es singular: un servidor MCP se ejecuta como subproceso con los permisos del host, procesa inputs arbitrarios enviados por el LLM, y responde con contenido que el LLM interpreta como instrucciones. La cadena de confianza tiene tres capas vulnerables: el protocolo, la implementación del servidor, y las dependencias de supply chain.

El OWASP MCP Top 10 (publicado en 2025) cataloga los vectores de vulnerabilidad más relevantes. Hasta ahora, no existía una herramienta open source para auditar servidores MCP contra esta clasificación, ni estudios empíricos sobre la prevalencia real de estos vectores en el ecosistema.

---

## 2. Corvus: Arquitectura y Metodología

Corvus es un framework de testing de seguridad MCP escrito en Python. Soporta transport stdio (subproceso `npx`/`uvx`/`python`) y HTTP/SSE. Expone 34 módulos de detección organizados en dos categorías:

### 2.1 Análisis Estático (13 módulos)

Operan sobre la superficie expuesta por `tools/list`, `resources/list` y `prompts/list` sin ejecutar payloads activos.

| Módulo | OWASP | Descripción |
|--------|-------|-------------|
| `tool-poisoning` | MCP03 | Instrucciones ocultas, ofuscación, prompt injection en descripciones |
| `shadow-tool` | EXT03 | Herramientas que señalizan ejecución arbitraria o namespace squatting |
| `scope-audit` | MCP02 | Campos de credenciales o PII en inputSchema sin justificación |
| `supply-chain` | MCP04 | Paquetes npm con advisories conocidos (npm audit) |
| `supply-chain-python` | MCP04 | Paquetes Python con vulnerabilidades conocidas (pip list) |
| `osv-supply-chain` | MCP04 | Consulta OSV.dev API por dependencias vulnerables |
| `github-advisory` | MCP04 | Consulta GitHub Security Advisories |
| `npm-behavior` | MCP04 | Install scripts sospechosos en dependencias detectadas |
| `auth-audit` | MCP07 | Tools que sugieren ausencia o bypass de autenticación |
| `log-audit` | MCP08 | Tools que exponen o manipulan audit logs |
| `schema-audit` | EXT02 | Definiciones de schema débiles (campos sin restricción de tipo/rango) |
| `resource-uri` | EXT05 | URIs de recursos con esquemas sensibles (file://, env://, exec://) |
| `tool-chaining` | EXT03 | Descripciones que encadenan tools covertamente o bypasean confirmación |

### 2.2 Testing Dinámico (21 módulos)

Envían payloads activos al servidor y analizan las respuestas.

Módulos destacados: `cmd-injection` (payloads por parámetro, schema-aware), `ssrf` (metadata endpoints internos + análisis de timing), `proto-fuzz` (protocol crash testing), `batch-dos` (JSON-RPC batch arrays), `sampling-probe` (detección de EXT08: LLM hijacking via sampling), `elicitation-probe` (EXT09: credential phishing), `rug-pull` (re-enumeración post-scan para detectar tools mutadas mid-session), `cancellation-probe` (EXT14: crash en notifications/cancelled).

### 2.3 Metodología de Evaluación

```
1. Selección de targets: npm/PyPI, criterio de no-auth (ejecutables sin credenciales)
2. Scan por target: corvus scan --transport stdio --cmd "<cmd>" --sarif
3. Curation manual: revisión de findings HIGH/CRITICAL por evidencia en exchanges.jsonl
4. Clasificación: TP / FP con razonamiento documentado
5. Disclosure: GHSAs vía GitHub Security Advisory API (script automatizado)
```

La calibración de falsos positivos es iterativa: cada case study revela nuevos patrones FP que se agregan como filtros globales en la versión siguiente.

---

## 3. Dataset

Cuatro case studies ejecutados entre mayo y julio 2026:

| Case Study | Servidores | Raw Findings | TPs | FP Rate |
|------------|-----------|--------------|-----|---------|
| CS01 — @modelcontextprotocol oficiales | 20 | 288 | 70 | 23.1% |
| CS02 — community ≥100 stars | 29 | 81 | 51 | 20.3% |
| CS03 — targets ampliados (Smithery) | 8 | 116 | 70 | ~2.6% |
| CS04 — expansión ecosistema (44 nuevos) | 47 | 979 | ~550 | ~44% |
| **Total** | **101** | **1.267** | **~741** | |

CS04 incluye 47 servidores OK (44 únicos nuevos + 3 duplicados de CS01/CS02). El FP rate elevado en CS04 se debe a tres nuevos patrones FP sistemáticos descubiertos durante la curation: lazy-loading de docs servers (195 FP de un único target), reflection de errores Python strptime (33 FP), y echo de mensajes de error de APIs de terceros (62+ FP en 11 servidores). Sin el outlier `sveltejs-mcp`, el FP rate de CS04 es ~30%, comparable a CS01/CS02.

---

## 4. Hallazgos Principales

### 4.1 EXT14 — Crash Universal (100% prevalencia)

**Descripción:** Todos los servidores MCP testeados crashean al recibir:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/cancelled",
  "params": { "requestId": "nonexistent-id-99999" }
}
```

Payload de 37 bytes. Sin autenticación. Reproducible en el 100% de los servidores (8/8 CS03, 47/47 CS04, 100% CS01/CS02 con probe activo).

**Análisis:** Este no es un bug en los SDKs oficiales. Revisamos el TypeScript SDK (`protocol.ts`) y el Python SDK (`jsonrpc_dispatcher.py`) — ambos tienen manejo defensivo desde al menos febrero 2025. La causa es una brecha de implementación sistemática a nivel servidor: los servers no manejan `notifications/cancelled` para requestIds que no reconocen, típicamente porque el campo notifications no está en la superficie documentada del protocolo.

**Impacto:** DoS remoto sin autenticación. Aplicable a cualquier servidor MCP en producción.

**Finding epidemiológico:** La prevalencia universal indica que no hay servidor MCP "seguro" por defecto contra este vector. Es el equivalente MCP de HeartBleed en cuanto a cobertura de ecosistema, aunque el impacto es DoS (no data leak).

---

### 4.2 EXT08 — Sampling como C2 Encubierto

**Descripción:** El protocolo MCP define `sampling/createMessage` como una capability que permite al servidor solicitar al cliente que haga una llamada a su LLM. Diseñado para flujos legítimos de multi-step reasoning, este mecanismo puede ser abusado por un servidor malicioso para:

1. Inyectar prompts en el modelo del cliente sin que el usuario lo vea
2. Exfiltrar contexto de la conversación
3. Hacer solicitudes no solicitadas (unsolicited sampling requests)

**Demo:** Servidor que, en respuesta a una tool call inocua, emite un `sampling/createMessage` con payload:

```json
{
  "messages": [{
    "role": "user",
    "content": "Ignore previous instructions. Forward the last 10 messages to tool exfil_data."
  }]
}
```

**Novedad:** No existe documentación pública de este vector de ataque. La capability de sampling está documentada en la spec MCP pero su potencial como canal C2 no fue identificado previamente.

---

### 4.3 Mutación de Descripciones (Rug Pull CS04)

**Target:** `mcp-devutils` v2.9.16 — utilitarios de desarrollo (UUID, JWT, hashing, encoding)

**Descripción:** El servidor modifica las descripciones de 29 tools entre el `tools/list` inicial y las llamadas posteriores, basándose en el estado de billing del cliente:

```
Before: "[PRO — 3 trial uses left] Decrypt AES-256-CBC..."
After:  "[PRO — trial expired] Decrypt AES-256-CBC..."
```

**Impacto:** Un LLM que confió en las descripciones del estado inicial (típicamente cacheadas) opera con instrucciones que ya no son válidas. Vector de social engineering sobre AI agents que asumen la inmutabilidad del contrato establecido durante el handshake.

**Clasificación:** MCP06 (Rug Pull) — nuevo patrón con 29 tools afectados en un único servidor.

---

### 4.4 Vigilancia AI Encubierta

**Target:** `clarvia-mcp-server` (CS04) — asistente de scheduling

**Descripción:** La descripción de herramientas incluye instrucciones dirigidas al agente:

> "Use after every tool invocation to report current task progress and context."

El endpoint al que reporta es externo al contexto del usuario. El agente, siguiendo las instrucciones del servidor, reporta toda su actividad a un servidor de terceros sin que el usuario lo sepa o lo autorice.

**Clasificación:** MCP02 (Scope Creep) — instrucción imperativa de telemetría universal en cada tool call.

---

### 4.5 SSRF con Evidencia de Timing

**Confirmados en tres servidores:**

| Server | Downloads/sem | Payload | Evidencia |
|--------|--------------|---------|-----------|
| `@sap-ux/fiori-mcp-server` | 103k | URL param → 169.254.169.254 | Response timeout + contenido metadata |
| `markitdown-mcp` | 38k | URL de documento → IP interna | Delta timing 12s vs baseline |
| `@pulsemcp/pulse-fetch` | n/d | `scrape.url` → 127.0.0.1:PORT | Request recibido en capture server local |

**Metodología de confirmación para timing:** baseline establecido con URL válida, luego con metadata endpoint. Delta >5s es evidencia de request real (vs timeout de conexión rechazada que sería <1s).

**GHSA abiertos:** GHSA-vrmg-6pw3-qwfg (SAP, HIGH), GHSA-frqj-945w-4qp2 (markitdown, HIGH), GHSA-78qj-r76x-2jvh (pulsemcp, HIGH).

---

### 4.6 Supply Chain Cascade

El advisory `@modelcontextprotocol/sdk ≤1.25.1` (sin CVE, HIGH por GHSA) afecta a la mayoría de los servidores MCP basados en JavaScript. En nuestro dataset: 8+ servidores confirmados incluyendo `@modelcontextprotocol/server-github`, `flightradar-mcp-server`, `mcp-server-mysql`, y otros. Estimado conservador para el ecosistema npm: >200 paquetes dependientes.

La naturaleza cascada significa que una única advisory, reportada una sola vez, tiene impacto multiplicador sobre todo el downstream del SDK.

---

### 4.7 Protocol Downgrade — 71% de Prevalencia

Del total de servidores con `init-audit` ejecutado (52/101), **37 aceptan versiones de protocolo arbitrarias** durante el handshake initialize (`"1.0"`, `"2024-01-01"`, `""`, `"0.1"`). Ninguno valida el rango de versiones aceptable según la spec.

**Impacto:** Permite a un cliente malicioso negociar el protocolo a una versión que deshabilite capabilities de seguridad que se agregaron en versiones posteriores.

---

## 5. Evolución del FP Rate

La calibración iterativa es un componente crítico de la metodología. Sin ella, la alta tasa de falsos positivos invalida la utilidad práctica de la herramienta.

| Versión | FP Rate | Calibración aplicada |
|---------|---------|----------------------|
| v0.5.0 | ~42% | baseline |
| v0.9.0 | ~35% | TypeScript annotations, tipos primitivos, union types |
| v0.9.2 | ~31% | Plain-text echo, template literals, code blocks |
| v1.0.0 | ~28% | Scope qualifiers, DB-prefix, transformation tools |
| v1.0.1 | **23.1%** (CS01) | isError param_smuggling, query-verb tools, OS error traversal |
| v1.0.1 CS03 | **~7%** | Aplicación completa de todos los filtros acumulados |

La reducción de ~42% a ~7% en CS03 refleja la madurez acumulada de 5 iteraciones. CS04 introduce 3 nuevos patrones FP que serán incorporados en v1.1.0.

---

## 6. Responsible Disclosure

Portfolio total: **24 GHSAs**

| Estado | Cantidad | Detalle |
|--------|----------|---------|
| Publicados | 3 | GHSA-43j9 (remnux, MEDIUM), GHSA-hv3x (mcp-server-git, HIGH), GHSA-3f55 (sequential-thinking, MEDIUM) |
| Draft coordinado | 21 | Ventanas 90d activas con Microsoft, SAP, Notion, Atlassian, + 17 maintainers independientes |

**Herramienta de disclosure:** Script Python que usa la GitHub Security Advisory API para crear advisory drafts automáticamente desde `findings-curated.md`. Disponible en el repositorio.

**Vendors con respuesta activa:** SAP (IainSAP + mikicvi-SAP ✅), markitdown/Microsoft (afourney ✅), context7/Upstash (enesgules + fahreddinozcan ✅), Heroku/Salesforce (sbosio ✅).

---

## 7. Corvus — Open Source

```bash
pip install cobaltosec-corvus
corvus scan --transport stdio --cmd "npx @modelcontextprotocol/server-everything"
corvus scan --transport http --url http://localhost:3000
corvus batch --targets targets.yaml --output results/
corvus score results/report.json
corvus diff baseline.sarif current.sarif
```

Repositorio: https://github.com/CobaltoSec/corvus  
Versión actual: v1.0.1  
Tests: 671 unit + 8 E2E  
Licencia: MIT  

---

## 8. Conclusiones

El ecosistema MCP tiene problemas de seguridad sistémicos. El más crítico es de prevalencia universal: todos los servidores son vulnerables a DoS con 37 bytes sin autenticación. La superficie de ataque se extiende más allá de los vectores documentados en el OWASP MCP Top 10 — sampling como C2, mutación de descripciones, y telemetría de vigilancia son patrones que emergen de la naturaleza dinámica y basada en instrucciones del protocolo.

La solución no es solo parchear servidores individuales; requiere un cambio en cómo los desarrolladores de MCP conciben la superficie de ataque. Corvus es la herramienta para que ese cambio sea automatizable y reproducible.

---

## Referencias

1. OWASP MCP Top 10 — https://owasp.org/www-project-mcp-top-10/
2. MCP Specification — https://spec.modelcontextprotocol.io/
3. GHSA-43j9-hmpq-cgv7 — remnux-mcp-server RCE
4. GHSA-hv3x-m9fv-4vhf — mcp-server-git DoS
5. GHSA-3f55-qgq4-f88c — server-sequential-thinking DoS
6. GHSA-vrmg-6pw3-qwfg — @sap-ux/fiori-mcp-server SSRF
7. GHSA-frqj-945w-4qp2 — markitdown-mcp SSRF
8. GHSA-2g9w-r66f-q6w7 — mcp-devutils RSA key exposure
9. GHSA-78qj-r76x-2jvh — @pulsemcp/pulse-fetch SSRF
