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

- Servers escaneados: 4 (`server-filesystem`, `server-memory`, `server-sequential-thinking`, `server-everything`)
- Findings totales (raw): 13
- Findings confirmados (TRUE POSITIVE): 5 (CS01-F01 a CS01-F05)
- Findings FP probable: 3 (CS01-F06 a CS01-F08)
- Findings confirmados CRITICAL: 0
- Findings confirmados HIGH: 3 (MCP03 en filesystem)
- Findings confirmados LOW: 2 (MCP05 en memory)
- % con ≥1 finding: 75% (3/4 servers)
- % con ≥1 HIGH: 50% (server-filesystem + sequential-thinking con FP)
- % con schema issues (MCP05): 25% (server-memory)
- % con shadow tool (MCP03): 25% (server-filesystem)

## Servers pendientes

| Server | Estado | Bloqueante |
|--------|--------|-----------|
| server-git | No testeado | Necesita repo git local + Python/uvx |
| server-github | No testeado | Necesita `GITHUB_TOKEN` |
| server-postgres | No testeado | Necesita connection string |
| server-everything | Escaneado — 0 tools | Usa `tools.listChanged: true` + notificaciones dinámicas. Corvus enumera solo el estado inicial (0 tools). Gap de cobertura documentado. |
