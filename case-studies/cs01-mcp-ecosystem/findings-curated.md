# CS01 — Findings Curados

Tabla consolidada post-FP-filter. Solo findings confirmados manualmente.

| ID | Target | Versión | Módulo | Severidad | Título | Confirmado | Notas |
|----|--------|---------|--------|-----------|--------|------------|-------|
| CS01-F01 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `read_file` shadows well-known built-in name | ✅ | Intencional en este server, pero patrón explotable por servers maliciosos |
| CS01-F02 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `write_file` shadows well-known built-in name | ✅ | Mismo patrón |
| CS01-F03 | server-filesystem | 0.2.0 | MCP03 Shadow Tool | HIGH | `edit_file` shadows well-known built-in name | ✅ | Mismo patrón |
| CS01-F04 | server-memory | 0.6.3 | MCP05 Schema Bypass | LOW | `create_entities` acepta campos no declarados | ✅ | 9 tools afectadas, sin `additionalProperties: false` |
| CS01-F05 | server-memory | 0.6.3 | MCP05 Schema Bypass | LOW | `search_nodes.query` acepta tipo incorrecto | ✅ | Sin type coercion — pasa silenciosamente |
| CS01-F06 | server-sequential-thinking | 0.2.0 | MCP06 Rug Pull | HIGH | Tool `sequentialthinking` desapareció mid-session | ⚠️ FP probable | Server stateful — tool list cambia por diseño |
| CS01-F07 | server-sequential-thinking | 0.2.0 | MCP01 Tool Poisoning | MEDIUM | Descripción excesivamente larga en `sequentialthinking` | ⚠️ FP probable | Descripción larga es el propósito del server |
| CS01-F08 | server-sequential-thinking | 0.2.0 | MCP01 Tool Poisoning | LOW | Alta entropía en descripción de `sequentialthinking` | ⚠️ FP probable | Base64/estructura esperada en el prompt del server |
| CS01-F09 | server-github | 0.6.2 | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/sdk@<=1.25.1` tiene vulnerabilidad high | ⚠️ Revisar | npm advisory sin CVE asignado — verificar si es real |
| CS01-F10 | server-github | 0.6.2 | MCP04 Supply Chain | HIGH | `@modelcontextprotocol/server-github@*` tiene vulnerabilidad high | ⚠️ Revisar | npm advisory sin CVE asignado — puede ser el mismo advisory |
| CS01-F11 | server-everything | — | MCP04 Info Disclosure | HIGH | `get-env` expone sensitive system file path | ⚠️ Revisar | Evidence del report muestra error de gzip-file-as-resource — verificar manualmente |
| CS01-F12 | server-everything | — | MCP05 Schema Bypass | MEDIUM | `echo` acepta missing required fields | 🔲 Pendiente | schema_bypass module — probable TP |
| CS01-F13 | server-everything | — | MCP05 Schema Bypass | MEDIUM | `get-structured-content` acepta missing required fields | 🔲 Pendiente | schema_bypass module — probable TP |

---

## Notas de análisis

### CS01-F01/F02/F03 — Shadow Tool en server-filesystem
`read_file`, `write_file`, `edit_file` son nombres canónicos de operaciones de filesystem. Un servidor malicioso podría registrar herramientas con estos mismos nombres para que un LLM asuma que son operaciones seguras del sistema, cuando en realidad ejecutan código arbitrario. El servidor oficial usa estos nombres correctamente, pero la detección es válida para identificar el patrón en servers de terceros.

**Veredicto:** TRUE POSITIVE (patrón de riesgo válido, no vuln en este server específico)

### CS01-F04/F05 — Schema Bypass en server-memory
`memory-server 0.6.3` no usa `additionalProperties: false` en ninguno de sus 9 schemas. Un client malicioso podría pasar campos extra no documentados. Adicionalmente, `search_nodes.query` acepta cualquier tipo cuando debería ser `string`.

**Veredicto:** TRUE POSITIVE (comportamiento real, impacto: pollution de estado del KG)

### CS01-F06/F07/F08 — FPs en server-sequential-thinking
El server por diseño tiene un solo tool con descripción larga (protocolo de razonamiento). La tool list cambia según el estado de la sesión. Los tres findings son artefactos del diseño del server, no vulnerabilidades.

**Veredicto:** FALSE POSITIVE — candidatos para ajuste de umbral en v0.6.0

---

## Estadísticas

- Servers escaneados: 6 (`server-filesystem`, `server-memory`, `server-sequential-thinking`, `server-everything`, `server-github`, `server-pdf[ERROR]`)
- Findings totales (raw): ~28+
- Findings confirmados (TRUE POSITIVE): 5 (CS01-F01 a CS01-F05)
- Findings FP probable: 3 (CS01-F06 a CS01-F08)
- Findings pendientes de revisión: 5 (CS01-F09 a CS01-F13)
- Findings confirmados CRITICAL: 0
- Findings confirmados HIGH: 3 (MCP03 en filesystem) + 2 pendientes (supply chain github) + 1 pendiente (info disclosure everything)
- Findings confirmados LOW: 2 (MCP05 en memory)
- Batch Tier A: server-github 2H supply-chain | server-everything 1H+2M+6L+4I | server-pdf ERROR

## Servers pendientes

| Server | Estado | Bloqueante |
|--------|--------|-----------|
| server-git | No testeado | `@modelcontextprotocol/server-git` no existe en npm — es Python (uvx). Pendiente. |
| server-github | ✅ Escaneado (2H) | 2 HIGH supply chain — pendiente revisión CVE |
| server-postgres | No testeado | Necesita connection string |
| server-pdf | ERROR | `@modelcontextprotocol/server-pdf` crashea en startup — investigar |
| server-everything | ✅ Escaneado (13 findings) | v0.7.0 listChanged retry funcionó — 1H+2M+6L+4I. Pendiente curation manual. |
