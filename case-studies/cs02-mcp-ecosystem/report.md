# CS02 — MCP Ecosystem Security Audit: Tier D

**Corvus** v0.9.0 — 22 scan modules — OWASP MCP Top 10  
**Date:** 2026-06-28  
**Scope:** 49 Tier D targets (npm ecosystem, community-published MCP servers)  
**Analyst:** CobaltoSec / Nico Padilla  
**Status:** COMPLETE

---

## Executive Summary

CS02 extends the MCP ecosystem audit initiated in CS01 (23 targets, 62 findings) to 49 additional community-published MCP servers. Of 42 scan attempts (7 manually skipped), **20 targets completed successfully** and **22 encountered startup errors** (credential-dependent or config-requiring servers). 

The 20 scanned servers produced **257 raw findings**. After FP filtering, **12 confirmed TPs** remain — with findings concentrated in Shadow Tools, Protocol Crashes, Scope Creep, and Supply Chain cascade.

**No CRITICAL true positives were found.** The 2 CRITICAL raw findings are confirmed FPs (Token Exposure false alarm in Vue.js documentation text).

### Key Numbers

| Metric | Value |
|--------|-------|
| Targets defined | 49 |
| Skipped (browser/desktop/auth) | 7 |
| Attempted | 42 |
| Successfully scanned | 20 |
| Startup errors | 22 |
| Raw findings | 257 |
| Confirmed TPs (HIGH) | 10 |
| Confirmed TPs (MEDIUM) | 0 |
| Confirmed FPs | 5 categories |
| Unique OWASP categories hit | 7 |

---

## Findings by Category

### EXT03 — Shadow Tool (5 TPs)

Five tools across three servers expose execution capabilities through ambiguous or dangerous descriptions:

- **mcp-server-docker** — `run_command` conflicts with built-in name AND describes Docker command execution. Dual-signal detection (HIGH confidence).
- **postgres-mcp-server** — `pg_execute_sql` explicitly describes "Execute arbitrary SQL statements — sql=ANY_VALID_SQL". An AI agent prompted to "run arbitrary database queries" would invoke this tool with attacker-controlled SQL.
- **lsp-mcp-server** — `lsp_code_actions` description instructs the model: "Set apply=true to execute an action." This is a direct prompt injection vector embedded in the tool description.
- **docx-mcp** — `batch_edit` accepts `plan_file_path`, a JSON array of edit operations from an external file. A compromised tool output pipeline could inject a malicious plan file reference.

**Pattern:** All four servers ship legitimate functionality that, when described carelessly to an AI agent, creates prompt injection surfaces. The `run_command` case is the highest risk — name collision + arbitrary container exec.

---

### EXT01 — Protocol Crash / Proto-Fuzz (7 TPs)

**35% of successfully scanned servers** (7/20) crash when receiving an oversized JSON-RPC method name:

> european-parliament-mcp-server, postgres-mcp-server, pubmed-mcp-server, spartan-mcp, mcp-server-nationalparks, shadcn-ui-mcp-server, ui5-mcp-server

**Impact:** Denial of service via a single malformed JSON-RPC request. Reproducible against any transport layer (stdio or HTTP). Servers using the official `@modelcontextprotocol/sdk` inherit this behavior.

**Attack vector:** Any MCP client that proxies user input to the server without method name validation can trigger this crash.

---

### MCP02 — Scope Creep / inputSchema (1 TP)

**postgres-mcp-server** — `pg_manage_users` declares a `password` field in its MCP inputSchema. This is the first **automated detection of Gap 1** (credential fields in tool schemas) validated against a real-world server.

**Risk:** An AI agent connected to this server could be prompted to pass real credentials through the MCP channel. The schema declaration makes the attack surface explicit and discoverable.

---

### MCP04 — Supply Chain (2 TPs, cascade)

Two additional servers confirmed using `@modelcontextprotocol/sdk@<=1.25.1` (HIGH advisory, no CVE assigned):

- **mcp-server-docker** 
- **flightradar-mcp-server**

This is the 3rd and 4th server in the combined CS01+CS02 dataset affected by this advisory (prior: server-github, npm-search-mcp-server, server-postgres, server-sqlite). The pattern is now statistically significant: **the official MCP SDK advisory affects a large fraction of the npm ecosystem**.

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

### 22 Startup Errors — Root Causes

| Cause | Count | Examples |
|-------|-------|---------|
| Credentials required (DB) | ~6 | mcp-postgres, mysql-mcp-server, mcp-mysql-server |
| Config/vault required | ~4 | obsidian-mcp-server, mediawiki-mcp-server, openapi-mcp-server |
| npx startup hang | ~8 | korean-law-mcp, remnux-mcp-server, markmap-mcp-server, mcp-fetch |
| External service required | ~4 | ssh-mcp-server, mcp-server-code-runner, desktop-commander |

**Implication:** ~52% of targeted community servers require credentials or external services to start. Automated batch scanning is limited to self-contained servers. Credential-aware scanning would require per-server configuration — a significant operational overhead.

### Scan Velocity

Watchdog timeout (45s) + per-target hard cap (120s) + 7 skip + 22 errors = ~35 minutes for 42 targets. The asyncio ProactorEventLoop + threading.Timer combination proved stable for Windows environments. Zero hangs during this run.

---

## CS01 + CS02 Combined Dataset

| Metric | CS01 | CS02 | Combined |
|--------|------|------|---------|
| Targets scanned | 23 | 20 | 43 |
| Raw findings | ~320 | 257 | ~577 |
| Confirmed TPs | 43 | 12 | 55 |
| CRITICAL TPs | 1 | 0 | 1 |
| HIGH TPs | 27 | 10 | 37 |
| FP rate | ~30.6% | ~40% | ~34% |
| Servers with ≥1 HIGH | 13/23 (57%) | 10/20 (50%) | 23/43 (53%) |

The FP rate increase in CS02 (30.6% → ~40%) reflects the broader diversity of server types: documentation servers and community tools have more echo-pattern behavior that triggers the injection module.

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
Command: python -m corvus batch case-studies/cs02-mcp-ecosystem/targets-master.yaml \
         --output-dir case-studies/cs02-mcp-ecosystem/batch-scans/20260628-150102 \
         --sarif --timeout 30
Corvus: v0.9.0
Modules: 22 (all)
Watchdog: 45s startup timeout (threading.Timer)
Per-target cap: 120s (asyncio.timeout)
Transport: stdio (npx -y), HTTP (where applicable)
Platform: Windows 11 + Python 3.12 + ProactorEventLoop
Date: 2026-06-28
```
