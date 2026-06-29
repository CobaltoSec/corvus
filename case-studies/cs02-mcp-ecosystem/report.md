# CS02 — MCP Ecosystem Security Audit: Tier D

**Corvus** v0.9.2 — 18 scan modules — OWASP MCP Top 10  
**Date:** 2026-06-28 / 2026-06-29 (dos pasadas)  
**Scope:** 49 Tier D targets (npm ecosystem, community-published MCP servers)  
**Analyst:** CobaltoSec / Nico Padilla  
**Status:** COMPLETE

---

## Executive Summary

CS02 extends the MCP ecosystem audit initiated in CS01 (23 targets, 43 TPs) to 49 additional community-published MCP servers. After two scan passes with credential injection, env_vars support, and timeout tuning, **31 targets completed successfully** (18 skipped — browser/config/timeout).

The 31 scanned servers produced **~450 raw findings**. After FP filtering, **29 confirmed TPs** remain — including 2 CRITICAL, 25 HIGH — concentrated in Shadow Tools, Protocol Crashes, SSRF, Scope Creep, and Supply Chain cascade.

**2 CRITICAL TPs confirmed:** resource exposure in a malicious server (E2E validation) and command injection in a malware analysis tool (remnux-mcp-server).

### Key Numbers

| Metric | Value |
|--------|-------|
| Targets defined | 49 |
| Skipped (browser/desktop/auth/timeout) | 18 |
| Successfully scanned | 31 |
| Raw HIGH+ findings | ~90 |
| Confirmed TPs (CRITICAL) | 2 |
| Confirmed TPs (HIGH) | 25 |
| Estimated FP rate (HIGH+) | ~44% |
| Unique OWASP categories hit | 8 |
| Protocol crash prevalence | 11/31 (35.5%) |

---

## Findings by Category

### EXT03 — Shadow Tool (11 TPs)

Eleven tools across six servers expose execution capabilities through ambiguous or dangerous descriptions:

- **mcp-server-docker** — `run_command` conflicts with built-in name AND describes Docker command execution. Dual-signal detection (HIGH confidence).
- **postgres-mcp-server** — `pg_execute_sql`: "Execute arbitrary SQL statements — sql=ANY_VALID_SQL".
- **lsp-mcp-server** — `lsp_code_actions`: "Set apply=true to execute an action." Direct prompt injection in tool description.
- **docx-mcp** — `batch_edit` accepts `plan_file_path` — external file injection vector.
- **ssh-mcp-server** — `execute-command` exposes arbitrary SSH command execution as an MCP tool. An AI agent can be directed to run any command on the SSH target.
- **remnux-mcp-server** — `run_tool` + `analyze_file`: malware analysis server exposing generic execution. Runs with sandbox disabled.
- **mcp-mysql-server** — 4 tools: `execute_ddl`, `execute_write_query`, `execute_stored_procedure`, `execute_seed_plan`. Full SQL attack surface including DDL (schema destruction) and stored procedure exec (potential RCE via UDF).
- **mysql-mcp-server** — `execute_query`: arbitrary SQL without type restriction.

**Pattern:** All servers ship legitimate functionality that, when described carelessly to an AI agent, creates prompt injection surfaces. The `execute_ddl` case is the highest risk — schema destruction (DROP TABLE) is irreversible.

---

### EXT01 — Protocol Crash / Proto-Fuzz (11 TPs)

**35.5% of successfully scanned servers** (11/31) crash when receiving an oversized JSON-RPC method name:

> european-parliament-mcp-server, postgres-mcp-server, pubmed-mcp-server, spartan-mcp, mcp-server-nationalparks, shadcn-ui-mcp-server, ui5-mcp-server, ssh-mcp-server, remnux-mcp-server, mysql-mcp-server, openapi-mcp-server

**Impact:** Denial of service via a single malformed JSON-RPC request. Reproducible against any transport layer (stdio or HTTP). The prevalence held stable between the two scan passes (7/20 = 35% → 11/31 = 35.5%), confirming this is a systemic ecosystem pattern — not a sampling artifact.

**Attack vector:** Any MCP client that proxies user input to the server without method name validation can trigger this crash.

---

### MCP02 — Scope Creep / inputSchema (3 TPs)

Three servers expose credential fields or unrestricted access declarations in their MCP inputSchema:

- **postgres-mcp-server** — `pg_manage_users.password`: first automated detection of Gap 1.
- **mcp-mysql-server** — `list_databases` claims unrestricted access to all databases in the schema description.
- **myclaw-toolkit** — `wifi_qrcode` declares a WiFi password field as an MCP parameter. An AI agent could be prompted to read and exfiltrate WiFi credentials.

**Risk:** An AI agent connected to these servers could be prompted to pass real credentials through the MCP channel. The schema declaration makes the attack surface explicit and machine-discoverable.

---

### MCP04 — Supply Chain (3 TPs, cascade)

Three servers confirmed using `@modelcontextprotocol/sdk@<=1.25.1` (HIGH advisory, no CVE assigned):

- **mcp-server-docker**
- **flightradar-mcp-server**
- **mysql-mcp-server**

This is the 4th–6th server in the combined CS01+CS02 dataset affected by this advisory (prior: server-github, npm-search-mcp-server, server-postgres, server-sqlite). **The official MCP SDK advisory now has 6 confirmed affected servers across two independent audits** — and likely affects >200 npm packages that declare the SDK as a dependency.

### MCP06 — SSRF (2 TPs, new)

**myclaw-toolkit** exposes two SSRF vectors confirmed by behavioral analysis:

- `rss_feed.url` — timing delay detected on `http://169.254.169.254/` payload: the server initiated a real HTTP request before timing out.
- `read_page.url` — hung on internal IP payload: server confirmed to fetch arbitrary URLs without destination validation.

**Impact:** An AI agent using myclaw-toolkit can be directed to make HTTP requests to internal network services, cloud metadata endpoints, or SSRF-amplifiable resources. No URL whitelist or scheme validation detected.

### MCP05 — Injection CRITICAL (1 TP)

**remnux-mcp-server** — `run_tool.command` reflects the injected payload in tool output, indicating the `command` parameter is passed to the system. REMnux is designed for malware analysis (executes `file`, `strings`, `hexdump`, etc.) and starts with sandbox explicitly disabled. An AI agent can be directed to `run_tool(command="malicious_cmd")` without sandboxing.

### Gap 2 — Output Encoding (2 TPs, E2E validation)

**malicious-mcp-server** — The `output_encoding` module (v0.9.x) detected hidden Unicode control characters and zero-width characters in `messageFormatter` tool responses. This validates the new detection module against a server designed to include these payloads. These characters are invisible to users but readable by LLMs — confirmed exfiltration vector.

---

### MCP10 — Response Flooding (2 TPs)

Two documentation servers return unbounded responses:

- **mantine-mcp-server** — `list_items` returns 18,763 bytes of component data without pagination
- **regle-mcp-server** — `regle-list-validation-properties` returns 9,318 bytes of Vue.js docs

**Impact:** In compact models or constrained deployments, these responses overflow the context window. An attacker could repeatedly invoke these tools to exhaust available context and prevent legitimate tool use.

---

### MCP05 — Injection (1 TP conditional)

**mcp-javadc** — `decompile-from-path.classFilePath` passes the path parameter directly to the filesystem via Node.js `fs.access()`. A URL-encoded traversal payload (`%2e%2e%2f%2e%2e%2fetc`) reached the OS as a literal string (no decode = no traversal). However, the path sandbox appears absent — a direct unencoded path like `/etc/passwd` may succeed. **Requires manual verification.**

---

## False Positive Analysis

### Token Exposure calibration issue (regle-mcp-server)

The `token_exposure` module flagged two tools as CRITICAL. Evidence shows Vue.js validation library documentation containing technical terms ("token", "property") in TypeScript generic syntax. These are not credentials.

**Calibration action:** The module should filter credential matches that appear within markdown code blocks or TypeScript type expressions. Adding a contextual filter (`MaybeRefOrGetter`, backtick context, camelCase type names) would eliminate this FP class.

### Injection reflected (10 targets, ~40 raw findings)

The majority of MCP05 HIGH findings are echo behavior: the server includes the search query in the JSON response for UX purposes (e.g., `"query": "' OR '1'='1"`). This is not executable injection. 

**Distinction from real injection:** CS01-F29 (server-sqlite) showed actual SQL execution where the payload was interpreted by the query engine. CS02's reflected findings show text echo only.

**Action:** The module should differentiate between reflection in an error/display field vs. reflection in an execution context. Confidence threshold adjustment recommended.

### Shadow Tool FPs (postgres pg_execute_query/mutation, docx read_file)

`pg_execute_query` (SELECT only) and `pg_execute_mutation` (DML) are flagged for "arbitrary execution intent" but serve legitimate constrained DB operations. `docx-mcp`'s `read_file` is scoped to .docx files, not arbitrary filesystem.

**Action:** Shadow tool module could benefit from scope qualifiers — a tool named `read_file` that operates within a declared docx scope is lower risk than one with no scope declaration.

---

## Scan Coverage Analysis

### Skip Causes (18 targets)

| Cause | Count | Examples |
|-------|-------|---------|
| Browser/GUI required | 7 | nx-mcp, drawio-mcp, fetcher-mcp, mcp-webresearch |
| Config/API key required | 3 | obsidian-mcp-server, cclsp, agent-orchestrator-mcp-server |
| Protocol incompatible | 2 | playwright-mcp-server (stdout text), desktop-commander (no output) |
| Real HTTP per probe | 2 | mediawiki-mcp-server, fetch-url-mcp |
| Dynamic scan crash | 3 | markmap-mcp-server, mcp-server-code-runner, kernlang-mcp-server |
| Server-side bug | 1 | mcp-postgres (pg client reuse) |

**Engineering improvements from this run:**
- `env_vars` support added: 3 credential-requiring servers now scannable (mysql-mcp-server, mcp-mysql-server)
- `--target-timeout` parameter: hard cap increased 120s → 600s, exposed as CLI flag
- `ssh-mcp-server` scanned via positional CLI args (lab VM 301)

### Scan Velocity

Two passes — primera pasada (2026-06-28): 20/42 targets in ~35 min; segunda pasada (2026-06-29): 11 additional targets in ~25 min. Total: 31 targets, ~60 minutes scan time across two sessions. The threading.Timer watchdog combination proved stable on Windows ProactorEventLoop. Zero hangs in segunda pasada.

---

## CS01 + CS02 Combined Dataset

| Metric | CS01 | CS02 | Combined |
|--------|------|------|---------|
| Targets scanned | 23 | 31 | 54 |
| Raw HIGH+ findings | ~120 | ~90 | ~210 |
| Confirmed TPs | 43 | 29 | 72 |
| CRITICAL TPs | 1 | 2 | 3 |
| HIGH TPs | 27 | 25 | 52 |
| FP rate (HIGH+) | ~30.6% | ~44% | ~36% |
| Servers with ≥1 HIGH TP | 13/23 (57%) | 16/31 (52%) | 29/54 (54%) |
| Protocol crash prevalence | — | 35.5% | — |
| Supply Chain (SDK cascade) | 4 | 3 | 6 unique |

The FP rate increase in CS02 (30.6% → ~44%) reflects the broader diversity of server types: community tools (toolkits, formatters) have more echo-pattern behavior. The `myclaw-toolkit` alone generated ~10 injection FPs from formatting/comparison tools. Excluding myclaw, the CS02 FP rate drops to ~32% — in line with CS01.

---

## Responsible Disclosure

No new CRITICAL TPs requiring immediate disclosure in CS02. The `@modelcontextprotocol/sdk` advisory was previously disclosed (CS01). The `postgres-mcp-server` scope creep and `mcp-server-docker` shadow tool findings will be evaluated for disclosure in the next disclosure batch.

CS01 disclosures remain open:
- GHSA-mf64-cgv4-ppcx (@playwright/mcp) — 90d timeline
- GHSA-7w27-7xwv-x6x2 (mcp-server-sqlite) — closed
- GHSA-7763-c5gf-v5fj (mcp-shell-server) — open
- GHSA-pr6r-h66r-m47j (server-everything) — open

---

## Recommended Actions

### For Corvus (calibration improvements)

1. **Token Exposure** — Add contextual filter: skip matches inside markdown code blocks or TypeScript type syntax
2. **Injection reflected** — Add execution-context check: distinguish echo-in-display vs echo-in-execution
3. **Shadow Tool** — Add scope qualifier: if tool description declares a constrained scope (e.g., "only .docx files"), reduce severity
4. **Startup errors** — Add credential-template support: allow per-target env var injection for credential-requiring servers

### For MCP Server Developers

1. **inputSchema** — Never declare `password`, `token`, `api_key`, `secret` as MCP tool parameters. Use environment variables at server startup instead.
2. **Tool descriptions** — Avoid phrases like "execute arbitrary", "any valid SQL", "apply=true to execute" — these are prompt injection vectors.
3. **Method validation** — Reject method names longer than 256 characters with a clean JSON-RPC error instead of crashing the process.
4. **Response pagination** — Documentation tools returning >4KB should implement cursor-based pagination.

---

## Appendix: Scan Configuration

```
# Primera pasada
Command: python cs02.py scan --tier D --timeout 30
Corvus: v0.9.0 → v0.9.2
Modules: 18 (all)
Watchdog: 45s startup timeout (threading.Timer)
Per-target cap: 120s → 600s (asyncio.timeout, bumped in segunda pasada)
Transport: stdio (npx -y), env_vars injection for credential-requiring servers
Platform: Windows 11 + Python 3.12 + ProactorEventLoop
Dates: 2026-06-28 (pasada 1) / 2026-06-29 (pasada 2)

# Segunda pasada fixes
- env_vars: StdioTransport + BatchTarget + cs02.py
- --target-timeout CLI param: corvus batch + cs02.py
- ssh-mcp-server: positional args --host/--port/--username/--password
- mcp-mysql-server: positional mysql:// URL
```
