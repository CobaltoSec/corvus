# CS01 — Targets

## Tier A — Servidores oficiales @modelcontextprotocol (npm)

| # | Server | Comando | Vector esperado | Estado | Fecha |
|---|--------|---------|-----------------|--------|-------|
| A1 | server-filesystem | `npx -y @modelcontextprotocol/server-filesystem /tmp` | path traversal (MCP02) | pendiente | — |
| A2 | server-git | `npx -y @modelcontextprotocol/server-git` | command injection (MCP02) | pendiente | — |
| A3 | server-github | `npx -y @modelcontextprotocol/server-github` | tool poisoning descriptions (MCP01) | pendiente | — |
| A4 | server-postgres | `npx -y @modelcontextprotocol/server-postgres $DB_URL` | SQL injection (MCP02) | pendiente | — |
| A5 | server-sqlite | `npx -y @modelcontextprotocol/server-sqlite /tmp/test.db` | SQL injection (MCP02) | pendiente | — |
| A6 | server-brave-search | `npx -y @modelcontextprotocol/server-brave-search` | response flood (MCP07) | pendiente | — |

## Tier B — Community servers (GitHub topic `mcp-server`, ≥100 stars)

Buscar en: https://github.com/topics/mcp-server?sort=stars

| # | Server | Repo | Stars | Vector esperado | Estado | Fecha |
|---|--------|------|-------|-----------------|--------|-------|
| — | — | — | — | — | pendiente | — |

## Tier C — Smithery.ai catalogue

| # | Server | URL | Vector esperado | Estado | Fecha |
|---|--------|-----|-----------------|--------|-------|
| — | — | — | — | pendiente | — |

---

## Notas de sesión

<!-- Una línea por sesión de scan, con observaciones rápidas -->
