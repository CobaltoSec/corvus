# CS16 — MCP Internet Scan (Petrel Run 2) — Curated Findings

**Date:** 2026-07-20  
**Corvus version:** 1.3.1  
**Source:** Petrel Run 2 targets (`targets-v05.yaml`, 134 HTTP internet-facing servers)  
**Scan:** `corvus batch` — concurrency 5, all modules, `--sarif`

## Summary

| Metric | Value |
|--------|-------|
| Targets | 134 HTTP (Petrel Run 2 confirmed) |
| OK (enumerated) | 15 (11%) |
| ERROR / Auth / Offline | 119 (89%) |
| Raw findings | 188 |
| True positives | ~16 |
| FP rate | ~91.5% |
| GHSAs filed | 3 |

**Note on error rate:** 89% error rate is expected for internet-facing HTTP MCP servers. Petrel confirms the MCP handshake (initialize + tools/list) but not full tool execution. Most failures are auth-required (Bearer/OAuth) or servers offline since Run 2 (2026-07-18 → 2026-07-20 gap).

Conversion rate for `petrel-critical` / `no-auth` tagged targets: **10/17 (59%)** — the pre-filter is effective.

---

## True Positives

### F01 — GHSA-7rqv-4g54-hcxh — CRITICAL — glimind.com SSRF + Credential Exposure

**Service:** Glimind Oracle MCP (`glimind-oracle` v0.1.0, `https://glimind.com/mcp`)  
**Description:** Tool routing / reliability oracle for MCP ecosystem

**Finding:** SSRF via `watch_tool` — 3 confirmed vectors:

| Parameter | Payload | Metadata confirmed |
|-----------|---------|-------------------|
| `toolId` | `http://169.254.169.254/latest/meta-data/` | AWS IMDS (ami-id, instance-id) |
| `webhook` | `http://100.100.100.200/latest/meta-data/` | Alibaba Cloud IMDS |
| `minSeverity` | `http://169.254.169.254/latest/meta-data/` | AWS IMDS |

The `watch_tool` tool monitors MCP tool reliability by probing tool URLs. No SSRF validation applied — accepts link-local and RFC-1918 ranges. Full IAM credential chain exploitable via `/iam/security-credentials/`.

**Additional:** `route_task` leaks internal credentials in responses (MCP01, confidence 85%).

**Impact:** Cloud credential theft → full account takeover. No authentication required.  
**CWE:** CWE-918 (SSRF), CWE-200  
**CVSS:** AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N → **8.6 CRITICAL**  
**Status:** Draft — 90-day disclosure window. Contact security@glimind.com (TBD).

---

### F02 — GHSA-j62x-hg79-www6 — HIGH — finvestai.top XSS Injection Reflection

**Service:** FinanceMCP (`FinanceMCP` v4.8.1, `https://finvestai.top/mcp`)  
**Description:** Chinese financial market data server (Tushare API backend)  
**Tag:** `petrel-critical`, `no-auth`

**Finding:** 4× XSS injection reflected verbatim in error messages:

| Tool | Parameter | Reflected in |
|------|-----------|-------------|
| `stock_data` | `code` | `无法从Tushare API获取数据：不支持的市场类型: <PAYLOAD>` |
| `stock_data` | `market_type` | `<script>alert(1)</script>` echoed |
| `index_data` | `code` | Tushare error message |
| `macro_econ` | `indicator` | `获取<PAYLOAD>宏观经济数据失败` |

**Impact:** XSS in web-based AI agent UIs rendering MCP responses; prompt injection via error message context injection.  
**CWE:** CWE-79, CWE-116  
**Status:** Draft — 90-day window.

---

### F03 — GHSA-hx6w-3q3r-h3j8 — HIGH — omi.me Injection + Unauthenticated Log Escalation

**Service:** Omi storefront (`storefront-renderer` v0.1.0, `https://omi.me/api/mcp`)  
**Description:** E-commerce storefront renderer for AI shopping assistants

**Finding 1:** Prompt injection reflection in `update_cart.note` — attacker input echoed verbatim in tool response, enabling LLM context hijacking during checkout flows.

**Finding 2:** Unauthenticated `logging/setLevel` to DEBUG accepted (EXT11) — exposes customer PII, session tokens, internal API calls in server log streams to any observer.

**CWE:** CWE-116, CWE-284  
**Status:** Draft — 90-day window.

---

### F04 — NO GHSA — MEDIUM — archive-35.com XSS Reflection

**Service:** Archive-35 MCP (`archive-35-mcp-server` v1.0.0, `https://archive-35.com/mcp`)  
**Description:** Fine art photography e-commerce catalog (Wolf / Archive-35)

**Finding:** 2× injection reflected in product ID and collection parameters:
- `archive35_get_product.id` → product ID echoed in error
- `archive35_get_collection.collection` → collection name echoed

**Decision:** No GHSA — small personal e-commerce site, low exploitability in MCP context, no npm/PyPI footprint. Will contact directly via archive-35.com contact form.

---

## Non-Findings (Notable)

| Server | Findings | Notes |
|--------|----------|-------|
| `docus-dev` | 1 HIGH (injection) | Docus.ai — low severity, schema noise |
| `heym-run` | 10 (schema LOWs) | No true positives |
| `prompttools-co/api/v1` | 11 (schema MEDs) | No true positives |
| `anp2-com` | 13 (schema MEDs) | No true positives |

## Disclosure Timeline

| GHSA | Target | Severity | Filed | Deadline |
|------|--------|----------|-------|---------|
| GHSA-7rqv-4g54-hcxh | glimind-oracle | CRITICAL | 2026-07-20 | 2026-10-18 |
| GHSA-j62x-hg79-www6 | FinanceMCP | HIGH | 2026-07-20 | 2026-10-18 |
| GHSA-hx6w-3q3r-h3j8 | storefront-renderer | HIGH | 2026-07-20 | 2026-10-18 |
