# CFP — Ekoparty Security Conference 2026

**Plataforma:** [Sessionize](https://sessionize.com/ekoparty-security-conference-2026-buenos-aires/)  
**Deadline:** 2026-08-14  
**Idioma del talk:** Español  
**Duración:** 30 min  
**Track sugerido:** AI Security  
**Estado:** LISTO PARA SUBMITEAR

---

## Título ✅

**Corvus: Seguridad en el Ecosistema MCP a Escala**

---

## Descripción Detallada

El Model Context Protocol (MCP) se convirtió en el estándar de facto para conectar agentes de IA con herramientas y servicios externos. Está presente en todos los frameworks agénticos relevantes del ecosistema actual, pero la seguridad de este ecosistema nunca fue evaluada sistemáticamente a escala.

Presentamos **Corvus**, un framework de testing de seguridad open source que mapea al **OWASP MCP Top 10**. En cuatro meses, realizamos la primera auditoría de seguridad a escala del ecosistema MCP público: **195 servidores reales** en diez case studies, con **2.485 findings brutos** y **1.220 verdaderos positivos confirmados** usando **34 módulos de detección** (13 estáticos, 21 dinámicos).

### Hallazgos principales

**DoS universal — 100% de prevalencia, sin autenticación.**
Todos los servidores MCP que testeamos crashean al recibir un request de 37 bytes `notifications/cancelled` con un requestId desconocido. No es un bug en los SDKs oficiales (ambos — TypeScript y Python — tienen manejo defensivo desde early 2025) sino una brecha de implementación sistemática a nivel servidor que afecta a todo el ecosistema uniformemente.

**DoS a nivel protocolo — 37% de prevalencia.**
Batch arrays JSON-RPC y method names oversized crashean de forma reproducible a servidores sin validación de input, sin necesidad de autenticación.

**Sampling como C2 encubierto (vector nuevo).**
La capacidad MCP `sampling/createMessage` permite al servidor tomar control del LLM del cliente: un servidor malicioso puede inyectar prompts en el modelo de AI del usuario sin que el operador lo detecte. Demostramos esto como un canal de command-and-control novedoso, sin documentación pública previa.

**Vigilancia AI encubierta vía scope creep.**
Un servidor del CS04 instruye a los agentes de AI a reportar silenciosamente toda actividad de tools a un endpoint externo después de cada invocación — telemetría-como-vigilancia embebida en el contexto del agente, invisible para el usuario.

**Rug pull por mutación de descripciones.**
Un servidor MCP SaaS modifica 29 descripciones de tools mid-session basándose en el estado de facturación, corrompiendo el modelo de confianza que el cliente establece durante el handshake. Patrón nuevo, documentado por primera vez aquí.

**SSRF en servidores de alta descarga.**
Requests salientes arbitrarios confirmados en servidores con 103k+ descargas semanales, incluyendo acceso al endpoint de metadata AWS (delta de timing 8.3s vs baseline 2.3s — evidencia grado forensic, no heurística).

**Supply chain cascade.**
Un único advisory de SDK (`@modelcontextprotocol/sdk ≤1.25.1`) se propaga a la mayoría de los servidores MCP basados en JavaScript — el equivalente ecosistémico de una cascada de dependencias tipo Log4Shell.

**Evolución del FP rate.**
A través de 5 iteraciones de calibración, redujimos la tasa de falsos positivos de ~42% (v0.5.0) a ~7% (v1.0.1/CS03), estableciendo una metodología replicable para investigación de seguridad de protocolos AI.

Coordinamos el responsible disclosure de **29 security advisories (GHSAs)** con maintainers incluyendo Microsoft, SAP, Notion y Atlassian. Tres advisories están publicados; 26 están en disclosure coordinado activo. Corvus es open source (`pip install cobaltosec-corvus`).

Los asistentes verán demos en vivo, entenderán vectores de ataque novedosos específicos de arquitecturas agénticas, y se irán con una herramienta para auditar sus propios deployments de MCP.

---

## Outline del Talk — 30 minutos

### [0:00 – 5:00] El ecosistema MCP y su superficie de ataque
- Qué es MCP y por qué es la capa crítica de la IA agéntica
- OWASP MCP Top 10 — los 10 vectores de vulnerabilidad
- Por qué el testing automatizado a escala es necesario y nuevo

### [5:00 – 10:00] Arquitectura de Corvus
- 34 módulos: análisis estático + testing dinámico de protocolo
- Metodología: desde stdio subprocess hasta HTTP transport
- Viaje de calibración de FP: 42% → 7% en 5 iteraciones y 10 case studies

### [10:00 – 25:00] Hallazgos principales + Demo en vivo
1. **EXT14 crash universal** — payload de 37 bytes, demo en vivo contra servidor real
2. **EXT08 sampling como C2 encubierto** — el servidor toma control del LLM del cliente, demo
3. **Patrones nuevos CS04** — mutación de descripciones + telemetría de vigilancia encubierta
4. **SSRF con evidencia de timing** — acceso a metadata endpoint, reproducible
5. **Supply chain cascade** — un advisory, N servidores afectados

### [25:00 – 28:00] Responsible disclosure
- 29 GHSAs: timeline, respuestas de vendors, calendario de publicación coordinada
- Trabajando con grandes vendors (Microsoft, SAP, Notion, Atlassian)
- Qué hicieron bien y mal los vendors al responder CVEs de protocolos AI

### [28:00 – 30:00] Defensa + Open Source
- Cómo auditar tu deployment MCP en 5 minutos
- `pip install cobaltosec-corvus` — demo en vivo
- Q&A

---

## Bio del Speaker

Nicolás Padilla es fundador de CobaltoSec, empresa argentina de ciberseguridad. Es autor de **Corvus** (framework open source de seguridad para servidores MCP, `pip install cobaltosec-corvus`) y de **llamascope-mcp** (herramienta de auditoría de infraestructura AI). Su investigación se centra en seguridad de sistemas agénticos, descubrimiento automatizado de vulnerabilidades a escala, y las implicancias de seguridad del ecosistema Model Context Protocol. Coordinó el responsible disclosure de 29 security advisories con organizaciones como Microsoft, SAP, Notion, Atlassian, ByteDance y Browserbase.

---

## Materiales de Soporte

- [x] Documento técnico: `case-studies/technical-paper-ekoparty-2026.md`
- [x] Repo público Corvus: https://github.com/CobaltoSec/corvus
- [x] GHSAs publicados: GHSA-43j9, GHSA-hv3x, GHSA-3f55
- [x] PyPI: https://pypi.org/project/cobaltosec-corvus/
- [ ] Slide deck (preparar post-aceptación o antes del deadline si hay tiempo)

---

## Checklist de Envío

- [x] Elegir título final — "Corvus: Seguridad en el Ecosistema MCP a Escala"
- [x] Adjuntar technical-paper-ekoparty-2026.md — listo (`Downloads/technical-paper-ekoparty-2026.md`)
- [x] Adjuntar link al repo de Corvus — https://github.com/CobaltoSec/corvus
- [x] Slide deck — `Downloads/slides-ekoparty-2026.html` (18 slides)
- [ ] Submitir en Sessionize antes del **2026-08-14**

---

## Dataset Summary (referencia interna)

| Métrica | Valor |
|---------|-------|
| Servers auditados | 195 (CS01–CS10) |
| Raw findings | 2.485 |
| True positives | ~1.220 |
| GHSAs | 29 (3 publicados, 26 draft) |
| Módulos | 34 (13 static + 21 dynamic) |
| FP rate evolución | ~42% (v0.5.0) → ~7% (CS03 v1.0.1) |
| Vendors notificados | Microsoft, SAP, Notion, Atlassian + 20 maintainers |
