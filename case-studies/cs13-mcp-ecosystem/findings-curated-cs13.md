# CS13 — Curated Findings (2026-07-06)

**Batch**: 32 targets | **OK**: 6 | **ERROR**: 26 (81%) | **New servers total**: 256
**Sources**: npm round 7 (salesforce/stripe/shopify/twilio/discord/notion/calendar/crm/ecommerce) + PyPI curated expansion

Note: 81% error rate — npm round 7 heavily skewed toward SaaS/auth-required servers (transcend×7, qingflow×2, kubernetes binary, xero, powerbi, gmail-oauth). PyPI curated packages mostly don't exist (prometheus, grafana, vault, terraform, openapi, arxiv).

---

## F01 — mcp-server-fetch — SSRF + Prompt Injection in fetch tool

| Field       | Value |
|-------------|-------|
| Package     | mcp-server-fetch (Anthropic, PyPI) |
| OWASP       | MCP05 (SSRF) + MCP09 (Prompt Injection) |
| Severity    | HIGH |
| Status      | TP — partially expected behavior |
| GHSA        | KNOWN-PATTERN — no GHSA (by design for fetch tools) |

**What**: The `fetch` tool shows:
1. SSRF (timing): `fetch.url` parameter → 169.254.169.254 probe delays (expected for an HTTP fetch tool)
2. Prompt template injection: `fetch` resource reflects fetched URL content verbatim, enabling web-delivered LLM injection

**Note**: SSRF is by design for a fetch tool — the tool explicitly fetches URLs. The prompt injection via fetched content IS a legitimate concern (webpages can inject LLM instructions), but Anthropic's own documentation acknowledges this limitation. Not a GHSA candidate — known behavior for fetch tools.

---

## F02 — gezhe-mcp-server — External log escalation to DEBUG

| Field       | Value |
|-------------|-------|
| Package     | gezhe-mcp-server (232/wk, Chinese PPT tool) |
| OWASP       | EXT11 (External Debug Escalation) |
| Severity    | HIGH |
| Status      | TP |
| GHSA        | LOW-PRI |

**What**: Server allows external log level escalation to DEBUG via MCP protocol. Verbose logging may expose internal request parameters, API tokens, or model identifiers.

**Note**: Same pattern as langsmith-mcp-server (CS12 F06). Low priority — limited impact for a PPT generation tool.

---

## Other OK Scans (no noteworthy findings beyond proto crashes)

| Server | Findings | Notes |
|--------|----------|-------|
| admina (MoneyForward) | 2 HIGH = proto crashes only | Auth-required service; proto crashes expected |
| ms-365 (@softeria) | 2 HIGH = proto crashes only | Auth-required Microsoft 365 service |
| square-mcp-server | 2 HIGH = proto crashes only | Auth-required Square payment API |
| duckduckgo-mcp-server | 2 HIGH = proto crashes only | Same package as CS08 (different YAML name) |

---

## Summary

| # | Package | OWASP | Severity | Status | GHSA? |
|---|---------|-------|----------|--------|-------|
| F01 | mcp-server-fetch | MCP05+MCP09 | HIGH | TP (by design) | NO — known pattern |
| F02 | gezhe-mcp-server | EXT11 | HIGH | TP | LOW-PRI |

**No new GHSA candidates this batch** — round 7 dominated by auth-required SaaS servers.

**FP noted**: `duckduckgo-py` scanned same package as CS08 `duckduckgo-mcp-server` — history name dedup issue.
