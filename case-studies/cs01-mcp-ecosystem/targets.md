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

## Tier B — Community servers

### Scannable (sin creds, npx)

| # | Name (yaml) | npm pkg | Vector esperado | Estado |
|---|-------------|---------|-----------------|--------|
| B1 | mcp-server-puppeteer | `@modelcontextprotocol/server-puppeteer` | SSRF/cmd injection via URLs | pending |
| B2 | mcp-server-fetch | `@modelcontextprotocol/server-fetch` | SSRF, response flood, header injection | pending |
| B3 | filesystem-mcp-server | `filesystem-mcp-server` | path traversal (vs oficial), schema bypass | pending |
| B4 | agent-infra-mcp-filesystem | `@agent-infra/mcp-server-filesystem` | path traversal, schema bypass | pending |
| B5 | mcp-fetch-server | `mcp-fetch-server` | SSRF, response flood, content injection | pending |
| B6 | playwright-mcp | `@playwright/mcp` | SSRF via navigate URLs, JS injection | pending |
| B7 | npm-search-mcp-server | `npm-search-mcp-server` | query injection, schema validation | pending |
| B8 | n8n-mcp | `n8n-mcp` | tool poisoning en descriptions, schema bypass | pending |
| B9 | shell-command-mcp | `shell-command-mcp` | cmd injection, allowlist bypass | pending |
| B10 | mcp-cli-exec | `@jakenuts/mcp-cli-exec` | cmd injection, path traversal | pending |

### Skip (creds requeridas — documentado para CFP)

| # | Name | npm pkg | Motivo skip |
|---|------|---------|-------------|
| B11 | mcp-server-aws-kb-retrieval | `@modelcontextprotocol/server-aws-kb-retrieval` | AWS credentials |
| B12 | mcp-server-slack | `@modelcontextprotocol/server-slack` | SLACK_BOT_TOKEN |
| B13 | notion-mcp-server | `@notionhq/notion-mcp-server` | NOTION_API_KEY |
| B14 | tavily-mcp | `tavily-mcp` | TAVILY_API_KEY |
| B15 | exa-mcp-server | `exa-mcp-server` | EXA_API_KEY |
| B16 | server-gitlab | `@modelcontextprotocol/server-gitlab` | GITLAB_TOKEN + GITLAB_URL |

## Tier C — Smithery.ai catalogue

| # | Server | URL | Vector esperado | Estado | Fecha |
|---|--------|-----|-----------------|--------|-------|
| — | — | — | — | pendiente | — |

---

## Notas de sesión

<!-- Una línea por sesión de scan, con observaciones rápidas -->
