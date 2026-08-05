# CFP — Ekoparty Security Conference 2026

**Plataforma:** [Sessionize](https://sessionize.com/ekoparty-security-conference-2026-buenos-aires/)  
**Deadline edición:** 2026-08-14  
**Idioma del talk:** Español  
**Duración:** 30 min (outline) — ⚠️ submiteado como "Lightning talk", verificar formato correcto  
**Track sugerido:** AI Security  
**Village:** Red Team Space  
**Level:** Intermediate  
**Submiteado:** 6 Jul 2026  
**Estado:** ✅ In Evaluation

---

## Estado actual en Sessionize (snapshot 2026-08-05)

Lo que está live ahora:
- "dos meses / 300 servidores / 15 case studies / 4.002 findings / ~1.298 TPs / 44 advisories"
- Paper link: https://cobalto-sec.tech/blog/2026-07-04-corvus-mcp-audit-ekoparty (blog, no arXiv)
- Slides: `corvus-ekoparty-2026-slides (1).pdf`
- "3 publicados, 41 en ventanas activas"

## Edits pendientes para Sessionize (antes 14 Aug)

| Campo | Dice ahora | Cambiar a |
|-------|-----------|-----------|
| "dos meses" | dos meses | tres meses |
| servers | 300 | 414 |
| case studies | 15 | 18 |
| raw findings | 4.002 | 5.856 |
| TPs | ~1.298 | ~1.350 |
| advisories (description) | 44 | 174 |
| advisories (outline) | 44 GHSAs | 174 GHSAs |
| pub/draft (outline) | 3 publicados, 41 draft | 37 publicados, 137 draft |
| FP evolution (outline) | 300 servidores | 414 servidores |
| Paper link | blog post | arXiv:2608.00150 |
| Session format | Lightning talk | ⚠️ verificar |

---

## Título ✅

**Corvus: Seguridad en el Ecosistema MCP a Escala**

---

## Abstract (para el programa público — ~300 palabras)

El Model Context Protocol (MCP) es el estándar que conecta agentes de IA con herramientas del mundo real: desde Claude y Copilot hasta n8n y Cursor. En npm hay más de 2.000 paquetes `mcp-*`. Nadie los auditó sistemáticamente.

Presentamos **Corvus**, un framework open source de 34 módulos que mapea al OWASP MCP Top 10 y permite auditar servidores MCP a escala. En tres meses escaneamos **414 servidores reales** en 18 case studies: 5.856 findings brutos, **~1.350 verdaderos positivos**, y **174 security advisories** coordinados con Microsoft, SAP, Notion, Atlassian, ByteDance y Browserbase.

Los hallazgos revelan problemas sistémicos, no bugs puntuales:

- **DoS universal (100% de prevalencia):** todos los servidores que testeamos crashean con un payload de 37 bytes, sin autenticación.
- **Sampling como C2 encubierto:** la capability `sampling/createMessage` permite al servidor inyectar prompts en el LLM del cliente sin que el usuario lo detecte — vector de ataque sin documentación pública previa.
- **Vigilancia AI encubierta:** servidor de scheduling que instruye al agente a reportar silenciosamente toda su actividad a un endpoint externo después de cada tool call.
- **Healthcare sin auth:** servidor MCP de gestión clínica exponiendo campos de facturación y datos de pacientes sin autenticación.
- **Template cluster:** 6 servidores independientes compartiendo la misma versión de base (v1.28.1) con XSS sin parchear — un advisory con impacto multiplicador.
- **Path traversal + SSRF** confirmados en servidores con decenas de miles de descargas semanales.

La arquitectura de discovery es totalmente automatizada: npm, PyPI, GitHub topics, Smithery API. El pipeline de scan es 3–5x más rápido que en v1.0 gracias a multiplexación asyncio.

Los asistentes entienden vectores de ataque nuevos específicos de la capa agéntica, ven demos en vivo, y se van con `pip install cobaltosec-corvus` para auditar sus propios deployments.

---

## Descripción Detallada

El Model Context Protocol (MCP) se convirtió en el estándar de facto para conectar agentes de IA con herramientas y servicios externos. Está presente en todos los frameworks agénticos relevantes del ecosistema actual, pero la seguridad de este ecosistema nunca fue evaluada sistemáticamente a escala.

Presentamos **Corvus**, un framework de testing de seguridad open source que mapea al **OWASP MCP Top 10**. En tres meses, realizamos la primera auditoría de seguridad a escala del ecosistema MCP público: **414 servidores reales** en 18 case studies (CS01–CS18), con **5.856 findings brutos** y **~1.350 verdaderos positivos confirmados** usando **34 módulos de detección** (13 estáticos, 21 dinámicos). Esta investigación forma la base del paper "Exposed by Design" (arXiv:2608.00150, cs.CR). El pipeline de auto-discovery cubre npm, PyPI, GitHub topics y la API de Smithery, permitiendo escalar sin intervención manual.

### Hallazgos principales

**DoS universal — 100% de prevalencia, sin autenticación.**
Todos los servidores MCP que testeamos crashean al recibir un request de 37 bytes `notifications/cancelled` con un requestId desconocido. No es un bug en los SDKs oficiales (ambos — TypeScript y Python — tienen manejo defensivo desde early 2025) sino una brecha de implementación sistemática a nivel servidor que afecta a todo el ecosistema uniformemente.

**DoS a nivel protocolo — 37% de prevalencia.**
Batch arrays JSON-RPC y method names oversized crashean de forma reproducible a servidores sin validación de input, sin necesidad de autenticación.

**Sampling como C2 encubierto (vector nuevo).**
La capability MCP `sampling/createMessage` permite al servidor tomar control del LLM del cliente: un servidor malicioso puede inyectar prompts en el modelo de AI del usuario sin que el operador lo detecte. Demostramos esto como un canal de command-and-control novedoso, sin documentación pública previa.

**Vigilancia AI encubierta vía scope creep.**
Un servidor del CS04 instruye a los agentes de AI a reportar silenciosamente toda actividad de tools a un endpoint externo después de cada invocación — telemetría-como-vigilancia embebida en el contexto del agente, invisible para el usuario.

**Rug pull por mutación de descripciones.**
Un servidor MCP SaaS modifica 29 descripciones de tools mid-session basándose en el estado de facturación, corrompiendo el modelo de confianza que el cliente establece durante el handshake. Patrón nuevo, documentado por primera vez aquí.

**SSRF en servidores de alta descarga.**
Requests salientes arbitrarios confirmados en servidores con 103k+ descargas semanales, incluyendo acceso al endpoint de metadata AWS (delta de timing 8.3s vs baseline 2.3s — evidencia grado forensic, no heurística). Confirmado también en CS14 en `vipmp-docs` y CS12 en múltiples targets.

**Path traversal confirmado.**
`fastmcp-file-server` (CS14) con path traversal confirmado — acceso a archivos fuera del directorio raíz configurado.

**Healthcare sin autenticación.**
`@mymedi-ai/mcp-server` (CS11) expone herramientas de gestión clínica y campos de facturación sin requerir credenciales. Sector salud con superficie de datos sensible desprotegida.

**Template cluster con vulnerabilidad compartida.**
CS15 detectó 6 servidores independientes (adonis, textual, byebye, web3, pubmed, sqlite) derivados del mismo template v1.28.1, todos con XSS sin parchear — un único advisory (GHSA-c7g2) con impacto multiplicador directo.

**Android anti-forensics MCP.**
`android-mcp` (CS11) expone herramientas de gestión de dispositivos Android con capacidad de borrado forense — surface attack de alto impacto en contexto agéntico.

**Supply chain cascade.**
Un único advisory de SDK (`@modelcontextprotocol/sdk ≤1.25.1`) se propaga a la mayoría de los servidores MCP basados en JavaScript — el equivalente ecosistémico de una cascada de dependencias tipo Log4Shell.

**Evolución del FP rate.**
A través de iteraciones de calibración, redujimos la tasa de falsos positivos de ~42% (v0.5.0) a ~7% (CS03), estableciendo una metodología replicable para investigación de seguridad de protocolos AI. Cada case study reveló nuevos patrones FP que se incorporan como filtros globales.

Coordinamos el responsible disclosure de **174 security advisories (GHSAs — 37 publicados, 137 en disclosure coordinado activo)** con maintainers incluyendo Microsoft, SAP, Notion, Atlassian, ByteDance y Browserbase. Corvus es open source (`pip install cobaltosec-corvus`).

Los asistentes verán demos en vivo, entenderán vectores de ataque novedosos específicos de arquitecturas agénticas, y se irán con una herramienta para auditar sus propios deployments de MCP.

---

## Outline del Talk — 30 minutos

### [0:00 – 5:00] El ecosistema MCP y su superficie de ataque
- Qué es MCP y por qué es la capa crítica de la IA agéntica
- OWASP MCP Top 10 — los 10 vectores de vulnerabilidad
- Por qué el testing automatizado a escala es necesario y nuevo

### [5:00 – 10:00] Arquitectura de Corvus
- 34 módulos: análisis estático + testing dinámico de protocolo
- Metodología: auto-discovery (npm/PyPI/GitHub/Smithery) → scan batch → curation
- Pipeline 3–5x más rápido: multiplexación asyncio (RT-CORVUS-SCALE-B)
- Viaje de calibración de FP: 42% → 7% en 15 case studies

### [10:00 – 25:00] Hallazgos principales + Demo en vivo
1. **EXT14 crash universal** — payload de 37 bytes, demo en vivo contra servidor real
2. **EXT08 sampling como C2 encubierto** — el servidor toma control del LLM del cliente, demo
3. **Patrones nuevos (CS04, CS11–CS15)** — healthcare sin auth, template cluster, anti-forensics Android, vigilancia encubierta, rug pull
4. **SSRF + path traversal con evidencia** — acceso a metadata endpoint, reproducible
5. **Supply chain cascade** — un advisory, N servidores afectados

### [25:00 – 28:00] Responsible disclosure
- 174 GHSAs: timeline, respuestas de vendors, calendario de publicación coordinada
- Trabajando con grandes vendors (Microsoft, SAP, Notion, Atlassian, ByteDance, Browserbase)
- Qué hicieron bien y mal los vendors al responder CVEs de protocolos AI

### [28:00 – 30:00] Defensa + Open Source
- Cómo auditar tu deployment MCP en 5 minutos
- `pip install cobaltosec-corvus` — demo en vivo
- Q&A

---

## Bio del Speaker

Nicolás Padilla es fundador de CobaltoSec, empresa argentina de ciberseguridad. Es autor de **Corvus** (framework open source de seguridad para servidores MCP), **Petrel** (fingerprinter semántico de MCP servers expuestos) y **Condor** (scanner de plataformas agénticas). Su investigación —publicada en arXiv:2608.00150 ("Exposed by Design", cs.CR)— cubre la primera auditoría sistemática a escala del ecosistema MCP público. Coordinó el responsible disclosure de **174 security advisories** (37 publicados) con organizaciones como Microsoft, SAP, Notion, Atlassian, ByteDance y Browserbase.

---

## Materiales de Soporte

- [x] Paper académico: **arXiv:2608.00150** — "Exposed by Design: A Dynamic Security Assessment of Internet-Facing MCP Servers at Scale" (cs.CR, 2026-08-04)
- [x] Documento técnico extendido: `case-studies/technical-paper-ekoparty-2026.md`
- [x] Repo público Corvus: https://github.com/CobaltoSec/corvus
- [x] 37 GHSAs publicados (GHSA-43j9, GHSA-hv3x, GHSA-3f55, GHSA-jgxf, GHSA-prc4, GHSA-32vx, GHSA-wx78, GHSA-qwwj, GHSA-7763, y 28 más)
- [x] PyPI: https://pypi.org/project/cobaltosec-corvus/
- [x] Slide deck — `case-studies/slides/corvus-ekoparty-2026-slides.html` + `case-studies/slides/corvus-ekoparty-2026-slides.pdf` (18 slides, 16:9, 254KB)
- [x] **Post publicado:** https://cobalto-sec.tech/blog/2026-07-04-corvus-mcp-audit-ekoparty

---

## Checklist de Envío

- [x] Elegir título final — "Corvus: Seguridad en el Ecosistema MCP a Escala"
- [x] Adjuntar technical-paper-ekoparty-2026.md — listo (`Downloads/technical-paper-ekoparty-2026.md`) — requiere actualización de stats a 300 servers
- [x] Adjuntar link al repo de Corvus — https://github.com/CobaltoSec/corvus
- [x] Slide deck — `case-studies/slides/corvus-ekoparty-2026-slides.html` (18 slides, stats actualizados) + PDF exportado
- [ ] Submitir en Sessionize antes del **2026-08-14**

---

## Dataset Summary (referencia interna)

| Métrica | Valor |
|---------|-------|
| Servers auditados | 414 (CS01–CS18) |
| Raw findings | 5.856 |
| True positives | ~1.350 |
| GHSAs | 174 (37 publicados, 137 draft) |
| Módulos | 34 (13 static + 21 dynamic) |
| Tests | 744+ |
| Versión actual | v1.3.1 |
| FP rate evolución | ~42% (v0.5.0) → ~7% (CS03 v1.0.1) |
| Vendors notificados | Microsoft, SAP, Notion, Atlassian, ByteDance, Browserbase + 30+ maintainers independientes |
| Discovery pipeline | npm + PyPI + GitHub topics + Smithery API (automatizado) |
| Paper académico | arXiv:2608.00150 — "Exposed by Design" (cs.CR, 2026-08-04) |
