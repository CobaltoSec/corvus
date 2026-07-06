# CS14 — Curated Findings (2026-07-06)

**Batch**: 68 targets | **OK**: 32 | **ERROR**: 36 (53%) | **New servers total**: 288
**Sources**: PyPI non-zero DL tier (top 35 by downloads) + verified packages (mcp-server-k8s, mcp-server-obsidian) + arxiv cluster (×10 variants) + docs/database 0-DL tier (×24)

Note: 32 OK / 36 ERROR. Errors dominated by auth-required services (filevine, canvas-local, bioinformatics, awslabs, oracle variants) and packages that don't exist on PyPI (csdb, fastmcp-analysis, convertfilefast, crowdsec, iflow-* variants).

---

## F01 — vipmp-docs-mcp — SSRF + Prompt Injection

| Field       | Value |
|-------------|-------|
| Package     | vipmp-docs-mcp (PyPI, 13/wk — SoftwareOne Adobe VIPM docs) |
| OWASP       | MCP05 (SSRF) + MCP09 (Prompt Injection × 2) |
| Severity    | HIGH |
| Status      | TP — GHSA filed |
| GHSA        | GHSA-grw7-4f4v-ffq9 |
| Maintainer  | smeeks-swo ✅ (SoftwareOne contributor) |

**What**:
1. `search_vipmp_docs.query` — SSRF (timing): outbound HTTP connections to attacker-controlled hosts via query parameter. A docs search server should not make external HTTP calls based on user query content.
2. `review_request_body` — MCP09 prompt injection: injected content reflected in tool response.
3. `debug_error_code` — MCP09 prompt injection: injected content reflected.

**Note**: SoftwareOne (enterprise software provider) documentation server for Adobe VIPM integration. SSRF in a docs server is unexpected — query likely interpolated into an API request URL. Vendored by enterprise AI deployments → elevated impact.

---

## F02 — fastmcp-file-server — Path Traversal + Shadow Tools

| Field       | Value |
|-------------|-------|
| Package     | fastmcp-file-server (PyPI, 0/wk) |
| OWASP       | MCP07 (Path Traversal) + MCP03 (Shadow Tool Naming) |
| Severity    | HIGH |
| Status      | TP — GHSA filed |
| GHSA        | GHSA-v2cj-6hxv-53r2 |
| Maintainer  | Luxshan2000 ✅ |

**What**:
1. `write_file.write-path` — unrestricted path parameter; no scope restriction, no chroot. `../../../etc/cron.d/backdoor` writes outside intended dir.
2. Shadow tools: registers `read_file`, `write_file`, `create_file`, `delete_file` — names conflict with built-in filesystem operations in many MCP clients (tool confusion vector).
3. EXT11: external log level escalation to DEBUG permitted without auth.

---

## F03 — arxiv cluster — XSS Reflection Pattern (9/10 variants)

| Field       | Value |
|-------------|-------|
| Packages    | arxiv-latex-mcp, arxiv-mcp, arxiv-mcp-pro, arxiv-paper-mcp, arxiv-paper-mcp-server, arxiv-query-mcp, arxiv-research-mcp, arxiv-search-mcp, arxiv-today-mcp |
| OWASP       | MCP04 (Output Encoding) |
| Severity    | MEDIUM |
| Status      | TP — same pattern as CS08 arxiv-latex finding |
| GHSA        | NO — already covered by GHSA-h6xq (CS08 arxiv-latex-mcp original) |

**What**: All 9 variants exhibit the same `<script>alert(1)</script>` XSS reflection in paper search/fetch tools. Systematic upstream template reuse across PyPI namespace variants — different package names, same vulnerable codebase. arxiv-search-mcp errored (package doesn't exist).

**Note**: No additional GHSAs — pattern is documented. Evidences widespread code copy-paste in academic tools namespace.

---

## F04 — secoda-analysis-mcp — Injection Reflected (PENDING VERIFY)

| Field       | Value |
|-------------|-------|
| Package     | secoda-analysis-mcp (PyPI, 11/wk — Secoda data catalog) |
| OWASP       | MCP09 (Prompt Injection) |
| Severity    | MEDIUM |
| Status      | PENDING-VERIFY — injection signal but may be parameter echo |
| GHSA        | PENDING — needs manual verification |

**What**: `get_resource.resource_id`, `get_collection.collection_id`, `get_question.question_id` reflect injection payload in tool response. Unclear if payload executes or is merely echoed in an error message.

**Action required**: Manual verification — call each tool with `CORVUS_INJECTION_TEST_{{7*7}}` and confirm whether the payload appears in LLM message context (TP) vs. error string only (FP).

---

## F05 — duckdbmcp — SSRF in URL loader (by-design)

| Field       | Value |
|-------------|-------|
| Package     | duckdbmcp (PyPI, 0/wk) |
| OWASP       | MCP05 (SSRF) |
| Severity    | LOW / BY-DESIGN |
| Status      | FP — intended behavior for URL data loading |
| GHSA        | NO |

**What**: `create_table_from_url.url` triggers SSRF timing. DuckDB supports loading CSV/Parquet from URLs — this is explicit design. An AI agent COULD be instructed to load from `169.254.169.254` but that's an indirect SSRF via intended functionality.

**Decision**: Not a GHSA candidate. Document as limitation of SSRF detector against URL-loader tools.

---

## Other OK Scans (no noteworthy findings)

| Server | Notes |
|--------|-------|
| bibtex-file-mcp | Proto crashes only |
| hackernews-niche | Proto crashes only |
| shadcn-docs-mcp | Clean — no findings above LOW |
| reflex-docs-mcp | Clean |
| openalex-ajg-mcp | Clean |
| docshelf-mcp, scoutdocs-mcp | Clean |
| local-ocr-mcp | Proto crashes only |
| file-tools-mcp | Clean |
| wikipedia-trends-mcp | Clean |
| netfile-mcp | SSRF + injection signals — no GitHub URL found for disclosure |
| file-reader-mcp, unifiles-mcp, file-downloader-mcp | Clean or proto only |
| docset (docsetmcp), your-docs-mcp | Clean |

---

## Summary

| # | Package | OWASP | Severity | Status | GHSA? |
|---|---------|-------|----------|--------|-------|
| F01 | vipmp-docs-mcp | MCP05+MCP09 | HIGH | TP | GHSA-grw7-4f4v-ffq9 ✅ |
| F02 | fastmcp-file-server | MCP07+MCP03 | HIGH | TP | GHSA-v2cj-6hxv-53r2 ✅ |
| F03 | arxiv cluster ×9 | MCP04 XSS | MEDIUM | TP | NO — covered by CS08 |
| F04 | secoda-analysis-mcp | MCP09 | MEDIUM | PENDING-VERIFY | PENDING |
| F05 | duckdbmcp | MCP05 | LOW/FP | BY-DESIGN | NO |

**CS14 GHSAs: 2 new** (GHSA-grw7 + GHSA-v2cj). secoda pending manual verify next session.
