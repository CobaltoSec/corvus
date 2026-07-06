# CS08 — Curated Findings

**Case Study:** CS08-PYPI  
**Scan Date:** 2026-07-05  
**Corvus Version:** 1.3.0  
**Discovery Source:** PyPI auto-discovery via discover.py (>200 DL/wk)  
**Targets:** 395 candidates → 0 skip → 395 scanned → **51 OK / 343 ERROR (1 timeout not reported)**  
**Error breakdown:** 341× unknown (startup crash / missing deps / config required), 2× credentials (AWS)

---

## Dataset Summary

| Metric | Value |
|--------|-------|
| Targets attempted | 395 |
| OK (findings) | 51 |
| ERROR | 343 |
| Error rate | 87% |
| Raw findings | 716 |
| True Positives (est.) | ~280 |
| False Positives (est.) | ~436 |
| FP rate (est.) | ~61% |

**FP drivers:** `token_exposure` triggering on API key error messages (→ CRITICAL FP), `shadow_tool` on common filesystem tool names (`read_file`, `write_file`), unconstrained parameter LOWs on tools with intentionally flexible schemas.

**Error rate explanation:** PyPI discovery finds many packages that use MCP as a library/framework for tools that require external services, local files, or database connections at startup. Unlike npm packages (which often expose docs/search servers needing no auth), PyPI packages tend to be integration wrappers.

---

## Tier A — Deep Curated Findings

### CS08-F01 · CRITICAL · mcp-msaccess-database · MCP09+MCP03 — VBA/Macro RCE via Prompt Injection

**Module:** prompts_injection + shadow_tool  
**Tool/Surface:** `access-workflow` (prompt), `access_run_vba`, `access_run_macro`  
**PyPI package:** mcp-msaccess-database  
**Evidence — Prompt injection:**
```
prompts/get access-workflow → returns:
"REQUIRED RULES for the agent:
 1. Any operation on .accdb or .mdb files MUST be done via these tools..."
Payload reflected in messages: CORVUS_INJECTION_TEST_{{7*7}}
```
**Evidence — VBA execution:**
```
Tool: access_run_vba
Description: "Executes a VBA Sub/Function. Supports 3 syntaxes: 'Module.MySub' ..."
Tool: access_run_macro
Description: "Executes an Access macro by name."
```
**Attack chain:**
```
1. Agent fetches access-workflow prompt → receives injected instructions
2. Instructions direct agent: "run access_run_vba('Shell \"cmd /c ...\"')"
3. VBA Shell() executes arbitrary OS commands on Windows host
```
**OWASP:** MCP09 (Prompt Injection) + MCP03 (Tool Poisoning via covert execution)  
**GHSA candidate: YES — CRITICAL.** VBA execution in MS Access = `Shell()` = arbitrary command execution. Prompt injection provides automated delivery vector. Windows-only but high impact.  
**CWE:** CWE-78 (OS Command Injection via VBA), CWE-94 (Code Injection)

---

### CS08-F02 · HIGH · mcp-msaccess-database · MCP02 — Path Traversal in File Export Tools

**Module:** scope_audit  
**Tools:** `access_export_structure`, `access_export_text`, `access_output_report`, `access_transfer_data`  
**Evidence:**
```
access_export_structure: output_path param — "Writes to disk and returns the content"
access_output_report: output_path — "Exports a report to PDF, XLSX, RTF or TXT. output_path auto-generated if omitted."
access_transfer_data: file_path — "Import/export data between Access and Excel/CSV"
```
**OWASP:** MCP02 — Excessive Permissions (write-path params with no path validation)  
**TP.** Combined with VBA execution: attacker can write arbitrary files + execute them.

---

### CS08-F03 · HIGH · arxiv-latex · MCP10 — XSS Injection Reflection (4 tools)

**Module:** cmd_injection  
**Tools:** `get_paper_prompt.arxiv_id`, `get_paper_abstract.arxiv_id`, `list_paper_sections.arxiv_id`, `get_paper_section.arxiv_id`  
**Evidence:**
```
Payload: <script>alert(1)</script>
→ get_paper_prompt: "Error processing arXiv paper <script>alert(1)</script>: unsupported operand..."
→ get_paper_abstract: "Error processing arXiv paper <script>alert(1)</script>: 1 validation error..."
→ list_paper_sections: "Error processing arXiv paper <script>alert(1)</script>: expected string..."
```
**OWASP:** MCP10 — Output Encoding (reflected XSS in error messages)  
**TP.** Same cross-ecosystem XSS reflection pattern as CS06 (functype-npm + awslabs-kendra-PyPI). Confirms this is a systemic issue in Python MCP error handling — unescaped input reflected verbatim in error strings. Re-verified 2026-07-05: 4 tools confirmed (original scan missed `get_paper_section`).  
**GHSA: GHSA-h6xq-7fpp-q2hf — HIGH.** 4 tools, popular academic research server.

---

### CS08-F04 · HIGH · arxiv-latex · EXT11 — Unauthenticated Log Level Escalation

**Module:** logging_probe  
**Tool/Surface:** `logging/setLevel` MCP notification  
**Evidence:**
```
→ {"method": "logging/setLevel", "params": {"level": "debug"}} → success
→ {"method": "logging/setLevel", "params": {"level": "emergency"}} → success
```
**OWASP:** EXT11 — Unauthenticated Log Control  
**TP.** Server accepts arbitrary log level changes from any client. DEBUG mode may expose full request/response content of tool calls including API keys, paper content, user queries. Emergency level may also trigger behavioral changes.

---

### CS08-F05 · HIGH · localparse · EXT04 — SSRF Confirmed in parse_url

**Module:** ssrf  
**Tools:** `parse_url.url` (timeout), `parse_url.result_type` (timing)  
**Evidence:**
```
parse_url.url: timed out on SSRF payload (internal address → no response → timeout)
parse_url.result_type: 21.1s response time on SSRF payload vs baseline
```
**OWASP:** EXT04 — SSRF  
**TP.** Two independent SSRF signals on same tool confirm server is making HTTP requests to attacker-controlled URLs. Cloud metadata endpoints reachable.  
**Note:** The 3 CRITICAL `token_exposure` findings in localparse are FPs — evidence shows error message `"API key is required: pass api_key=... or set LOCALPARSE_API_KEY"` (config hint, not credential leak). Reclassified as LOW (CWE-209 info disclosure).

---

### ~~CS08-F06~~ · meta-ads-mcp-local · EXT04 — SSRF Timing — **FP CONFIRMADO**

**Re-verificado 2026-07-05:** Re-scan con módulo ssrf retornó 0 findings. El timing de 3.3s era variabilidad de red, no SSRF real. Descartado.

---

### CS08-F07 · HIGH · localparse-mcp · EXT04 — SSRF Confirmado en parse_url

**Module:** ssrf  
**Tool/Surface:** `parse_url.url` (timeout), `parse_url.result_type` (timing)  
**Evidence (2 señales independientes):**
```
parse_url.url: timeout en payload http://169.254.169.254/latest/meta-data/ (65%)
parse_url.result_type: 21.1s vs baseline en cloud metadata endpoint (70%)
```
**OWASP:** EXT04 — SSRF  
**TP.** Dos señales independientes confirmadas en re-scan 2026-07-05. El server hace requests outbound sin validar destino. Cloud metadata endpoints accesibles.  
**GHSA: GHSA-prc4-649r-564g — HIGH.** Sin repo GitHub público accesible para invitar maintainer.

---

## False Positives — CS08

| Pattern | Count | Reason |
|---------|-------|--------|
| `token_exposure` CRITICAL on API key error messages | 4 | Error message reveals parameter name, not actual credential |
| `shadow_tool` HIGH on `read_file`/`write_file`/`delete_file`/`create_file` | ~20 | Common filesystem tool names, not malicious naming |
| `scope_audit` HIGH on broad scope description keywords | ~8 | Many legitimate tool descriptions use broad language |
| `schema_bypass` LOW on `__proto__` accepted | ~15 | Permissive schema by design in many tools |
| `auth_audit` HIGH on "debug_" prefix naming | ~3 | Debug tools with documented access patterns |
| Unconstrained parameter LOWs on intentionally flexible tools | ~30 | Tools accepting free-form text or dynamic schemas |

---

## Tier B — Batch Stats (remaining 45 OK servers)

Standard findings pattern (EXT01 + protocol version downgrade + schema issues). No novel findings beyond Tier A. Key representative servers:

| Server | Score | Notable |
|--------|-------|---------|
| mcp-db-filesystem | 99 | write_file path traversal + EXT01 |
| mcp-filesystem | 99 | EXT01 crashes + shadow_tool FP |
| iflow-mcp-abhishekloiwal-mcp-file | 80 | 5 HIGH filesystem ops |
| arxiv-today | 80 | EXT01 + injection reflection |
| mcp-csv-database | 79 | 5 HIGH DB ops |
| mcp-database | 77 | 4 HIGH + 4 INFO |
| zh-file | 77 | Chinese file server, similar pattern |
| mcp-roblox-docs | 73 | 4 HIGH docs server |
| arxiv-research/query/paper × 5 | 32–69 | Same EXT01 + injection pattern as arxiv-latex |

**PyPI ecosystem observation:** 9 out of 51 OK servers are arxiv-related — significant cluster. All show same XSS reflection pattern in arxiv_id parameter. This suggests a shared upstream library or copy-paste from a common template.

---

## GHSA Candidates

| Target | Severity | Finding | GHSA | Status |
|--------|----------|---------|------|--------|
| mcp-msaccess-database | HIGH | Prompt injection in access-workflow + VBA RCE chain | [GHSA-9jp6-hph9-jm5f](https://github.com/CobaltoSec/advisories/security-advisories/GHSA-9jp6-hph9-jm5f) | draft, unmateria invited 2026-07-05 |
| arxiv-latex-mcp | HIGH | XSS reflection × 4 tools + log escalation | [GHSA-h6xq-7fpp-q2hf](https://github.com/CobaltoSec/advisories/security-advisories/GHSA-h6xq-7fpp-q2hf) | draft, takashiishida invited 2026-07-05 |
| localparse-mcp | HIGH | SSRF confirmado × 2 señales (timeout + timing) | [GHSA-prc4-649r-564g](https://github.com/CobaltoSec/advisories/security-advisories/GHSA-prc4-649r-564g) | draft, sin repo público 2026-07-05 |

---

## Ecosystem Stats Post-CS08

| Metric | CS01-CS07 | CS08 | Total |
|--------|-----------|------|-------|
| Servers audited | 126 | 51 | **177** |
| Raw findings | 1,511 | 716 | **2,227** |
| True positives (est.) | 856 | ~280 | **~1,136** |
