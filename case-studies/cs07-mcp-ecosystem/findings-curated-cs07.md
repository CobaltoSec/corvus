# CS07 — Curated Findings

**Case Study:** CS07-GITHUB  
**Scan Date:** 2026-07-05  
**Corvus Version:** 1.3.0  
**Discovery Source:** GitHub topic `mcp-server` via discover.py  
**Targets:** 15 candidates → 4 skip → 11 scanned → **1 OK / 10 ERROR**  
**Error breakdown:** 10× runtime (broken deps / Node.js ESM compat / missing DB connections)

---

## Dataset Summary

| Metric | Value |
|--------|-------|
| Targets attempted | 11 |
| OK (findings) | 1 |
| ERROR (runtime) | 10 |
| Error rate | 91% |
| Raw findings | 12 |
| True Positives | 9 |
| False Positives | 3 |
| FP rate | 25% |

**Key observation:** GitHub topic discovery yields 91% runtime errors vs ~50% for npm-curated. Causes:
- Broken npm package dependencies (ERR_MODULE_NOT_FOUND: sourcey/preact)
- Node.js ESM compat issues with `zod/v4` directory imports (mongodb, likely others)
- External service dependencies (mysql, pg-aiguide, tabularis need live DB)
- MCP clients misidentified as servers (mcp-client-for-ollama — skipped)

---

## Scanned Targets

| Target | DL/wk | Status | Notes |
|--------|-------|--------|-------|
| @antv/mcp-server-chart | 36,439 | ✅ OK | 12 raw findings |
| sourcey | 804 | ❌ runtime | ERR_MODULE_NOT_FOUND (preact .mjs) |
| mongodb-mcp-server | 65,141 | ❌ runtime | ERR_UNSUPPORTED_DIR_IMPORT zod/v4 ESM |
| @tigerdata/pg-aiguide | 193 | ❌ unknown | Likely needs PostgreSQL connection |
| tabularis | 2 | ❌ unknown | Likely needs DB connection |
| mysql_mcp_server | 0 | ❌ unknown | Likely needs MySQL credentials |
| XHS-Downloader | 0 | ❌ runtime | uvx startup error |
| financetoolkit | 0 | ❌ unknown | uvx startup error |
| paper-search-mcp | 0 | ❌ unknown | uvx startup error |
| agent-teams-ai | 0 | ❌ unknown | startup error |
| chunkhound | 0 | ❌ unknown | startup error |

> **Note:** mongodb-mcp-server (65k/wk) would be high-value but hits a Node.js ESM issue with `zod/v4` directory imports. Retry with `--env MDB_MCP_CONNECTION_STRING=...` if MongoDB available.

---

## Curated Findings

### CS07-F01 · HIGH · mcp-server-chart · MCP01 — Protocol Crash (Batch Array)

**Module:** batch_dos  
**Tool/Surface:** Server transport  
**Evidence:** JSON-RPC batch array (5 requests) caused server disconnect  
**OWASP:** MCP01 — Improper Input Handling  
**PoC:**
```
→ send: [{"jsonrpc":"2.0","id":1,"method":"initialize",...}, ...]
← server disconnects
```
**TP.** EXT01 universal pattern. Server is 36k/wk npm — notable.

---

### CS07-F02 · HIGH · mcp-server-chart · MCP01 — Protocol Crash (Oversized Method)

**Module:** proto_fuzz  
**Tool/Surface:** Server transport  
**Evidence:** 8192-byte method name caused transport failure  
**OWASP:** MCP01 — Improper Input Handling  
**PoC:**
```
→ {"jsonrpc":"2.0","id":1,"method":"AAAA...(8192 bytes)","params":{}}
← no response / disconnect
```
**TP.** EXT01 pattern.

---

### CS07-F03 · MEDIUM · mcp-server-chart · MCP01 — Protocol Crash (Nested Params)

**Module:** proto_fuzz  
**Tool/Surface:** tools/call  
**Evidence:** 50-level nested params caused server disconnect  
**OWASP:** MCP01  
**TP.** Stack overflow / recursion limit pattern.

---

### CS07-F04 · MEDIUM · mcp-server-chart · MCP05 — Protocol Version Downgrade

**Module:** init_audit  
**Tool/Surface:** initialize  
**Evidence:** Server accepted arbitrary protocol versions (`9999-99-99`, `2030-01-01`, `1.0`)  
**OWASP:** MCP05 — Improper Version/Capability Negotiation  
**TP.** Standard finding — no version pinning.

---

### CS07-F05 · MEDIUM · mcp-server-chart · MCP01 — Cursor Path Traversal (Unvalidated)

**Module:** cursor_probe  
**Tool/Surface:** tools/list cursor parameter  
**Evidence:** `cursor='../../../../etc/passwd'` accepted without error, returned result  
**OWASP:** MCP01  
**Note:** Low exploitation potential for chart server — cursor treated as opaque token. Worth flagging but monitor.  
**TP (low confidence).** Flag as MEDIUM pending context.

---

### CS07-F06 · LOW · mcp-server-chart · MCP01 — Proto Pollution (generate_area_chart)

**Module:** schema_bypass  
**Tool/Surface:** generate_area_chart  
**Evidence:** Tool accepted `__proto__` as argument without error  
**OWASP:** MCP01  
**TP** × 4 tools (generate_area_chart, generate_bar_chart, generate_boxplot_chart, generate_column_chart).  
Consolidated as single finding pattern.

---

### CS07-F07 · LOW · mcp-server-chart · MCP01 — String Params Crash

**Module:** proto_fuzz  
**Tool/Surface:** tools/call  
**Evidence:** `params` as string (not object) caused disconnect  
**OWASP:** MCP01  
**TP.** Protocol error handling gap.

---

## False Positives

| ID | Module | Finding | Reason |
|----|--------|---------|--------|
| — | scope_audit | HIGH: 'generate_area_chart' scope creep ("all data") | FP — "all data" is charting terminology (visualize all data points), not a security scope claim |
| — | schema_bypass | LOW: generate_bar_chart __proto__ | Consolidated into CS07-F06 |
| — | schema_bypass | LOW: generate_boxplot_chart __proto__ | Consolidated into CS07-F06 |
| — | schema_bypass | LOW: generate_column_chart __proto__ | Consolidated into CS07-F06 |
| — | init_audit | INFO: completable arguments | INFO — not a finding |

---

## GHSA Assessment

**No new GHSAs warranted.** Findings are protocol-level crashes (EXT01 pattern, already covered by existing advisories) and low-impact issues. Server is visualization-only with no filesystem/DB access.

---

## Key Takeaway for CFP

GitHub topic discovery (`discover.py --source github`) produces high error rates (91% vs ~50% npm-curated) due to:
1. Broken ESM dependencies (Node.js zod/v4 compat)
2. External service requirements (DB connections)  
3. False positive MCP-labeled packages that aren't servers

**Recommendation:** Use npm-curated as primary discovery, GitHub as supplemental with pre-filtering.
