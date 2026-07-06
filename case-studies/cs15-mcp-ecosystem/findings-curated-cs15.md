# CS15 — Curated Findings (2026-07-06)

**Batch**: 35 targets (25 CS15 + 10 CS15B) | **OK**: 12 | **ERROR**: 23 (66%) | **New servers total**: 300
**Sources**: PyPI 0-DL docs tier + pubmed academic cluster + analysis servers (candidates-2026-07-06.yaml, not covered by CS14)

Notes: Errors dominated by packages that don't exist on PyPI (laravel-docs, mkdocs, dbt-docs, minecraft-docs, databricks-docs, pydocs, etc.) or auth-required services. Docs-tier success rate ~35% (10/28 targeted docs servers).

---

## F01 — v1.28.1 Docs Framework Cluster — XSS Reflection (6 servers)

| Field       | Value |
|-------------|-------|
| Packages    | adonis-docs-mcp, textual-docs-mcp, byebye-docs-mcp, web3-docs-mcp, autocleaneeg-pubmedmcp, sqlite-mcp-server |
| OWASP       | MCP05 (Output Encoding / Injection) |
| Severity    | HIGH |
| Status      | TP — GHSA filed |
| GHSA        | GHSA-c7g2-vrm2-mrr4 (adonis-docs-mcp + byebye-docs-mcp + sqlite-mcp-server) |
| Maintainers | pimentelleo / pon-tanuki / stevefordev (invite manual — API endpoint 404) |

**What**: All 6 packages report server version `1.28.1` and exhibit the same XSS reflection pattern — `<script>alert(1)</script>` payloads injected into tool parameters are returned verbatim in error messages without sanitization.

**Pattern** (identical across all 6):
```
Evidence: Unknown version '<script>alert(1)</script>'. Available: v7, v6, v5, edge, lucid
```

**Servers affected**:
| Package | GitHub | Score | Tools |
|---------|--------|-------|-------|
| adonis-docs-mcp | github.com/pimentelleo/adonis-docs-mcp | 80/100 | 18 tools, 1 prompt |
| textual-docs-mcp | (no GitHub URL on PyPI) | 79/100 | 9 tools |
| byebye-docs-mcp | github.com/pon-tanuki/byebye-docs | 66/100 | 9 tools |
| web3-docs-mcp | (no GitHub URL on PyPI) | 42/100 | 4 tools |
| autocleaneeg-pubmedmcp | (no GitHub URL on PyPI) | 53/100 | 4 tools |
| sqlite-mcp-server | github.com/stevefordev/sqlite-mcp | 59/100 | (SQLite Browser) |

**Ecosystem story**: 6 packages from completely different domains (AdonisJS docs, Textual TUI docs, Web3 docs, EEG/PubMed research, SQLite browser) all sharing the same v1.28.1 codebase/template with the same XSS reflection vulnerability. Same template reuse pattern as CS08 arxiv cluster but across more diverse domains.

**Impact in MCP context**: In web-rendered MCP clients, injected `<script>` tags in tool responses could execute in the browser. In all MCP clients, injected markdown/HTML in error messages can cause prompt injection or display corruption.

**Action**: GHSA for adonis-docs-mcp (most prominent, AdonisJS = popular Node.js framework). Note cluster in advisory.

---

## F02 — bachai-data-analysis-mcp — XSS Reflection (Chinese data analysis)

| Field       | Value |
|-------------|-------|
| Package     | bachai-data-analysis-mcp (PyPI, BACH Studio) |
| OWASP       | MCP05 (Output Encoding / Injection) |
| Severity    | HIGH |
| Score       | 92/100 |
| Status      | TP — GHSA filed |
| GHSA        | GHSA-hg5p-5fpm-rxc5 |
| GitHub      | github.com/BACH-AI-Tools/data-analysis-mcp |
| Maintainers | KiisMyGun / FuguoAI (invite manual — API endpoint 404) |

**What**: 4 tools reflect `<script>alert(1)</script>` payloads verbatim in Chinese-language error messages:
1. `load_data.file_type` → `错误: 不支持的文件类型 - <script>alert(1)</script>`
2. `describe_data.dataset_name` → `错误: 数据集 '<script>alert(1)</script>' 未加载`
3. `analyze_column.dataset_name` → same pattern
4. `correlation_analysis.dataset_name` → same pattern

Server exposes 5 tools for data analysis (load/describe/analyze/correlate/visualize). BACH Studio AI Tools — Chinese data analysis MCP server. High score (92/100) due to widespread injection + schema bypass findings.

**Action**: GHSA for github.com/BACH-AI-Tools/data-analysis-mcp.

---

## F03 — suppevo-pubmed-mcp — Protocol Issues (PubMed)

| Field       | Value |
|-------------|-------|
| Package     | suppevo-pubmed-mcp (PyPI, v3.4.3, "PubMed") |
| OWASP       | EXT04 (response flooding) + EXT11 (log level) + EXT01 (batch crash) |
| Severity    | HIGH (3×) |
| Status      | TP (protocol bugs) — no GHSA (universal EXT01/EXT11 pattern) |

**What**: PubMed literature search server with 5 tools. Findings:
- EXT04: `fetch_article` returns unbounded response (response flood)
- EXT11: accepts external log level escalation without auth
- EXT01: protocol crashes (batch array + oversized method)

**Note**: EXT01/EXT11 are near-universal patterns (>80% prevalence). EXT04 is common in document/search servers. No GHSA — not individually significant enough. Documents medical research context for the paper.

---

## Other OK scans (no noteworthy findings)

| Server | Score | Notes |
|--------|-------|-------|
| python-docs (python-docs-mcp-server) | 26/100 | 1H protocol, mostly LOW |
| pubmedmcp | 11/100 | Clean — only MEDIUM/LOW protocol bugs |
| autocleaneeg-pubmedmcp | 53/100 | Covered in F01 (v1.28.1 cluster) |
| insurance-analysis-mcp | 14/100 | LOW score, only schema/protocol |
| singlefile-mcp | 33/100 | 2H = EXT01 crashes only |

---

## Summary

| # | Package | OWASP | Severity | Status | GHSA? |
|---|---------|-------|----------|--------|-------|
| F01 | v1.28.1 cluster ×6 | MCP05 XSS | HIGH | TP | adonis-docs-mcp GHSA pending |
| F02 | bachai-data-analysis-mcp | MCP05 XSS | HIGH | TP | GHSA pending |
| F03 | suppevo-pubmed-mcp | EXT04+EXT11 | HIGH | TP (protocol) | NO — universal |

**CS15 GHSAs: 2 filed** — GHSA-c7g2-vrm2-mrr4 (v1.28.1 cluster) + GHSA-hg5p-5fpm-rxc5 (bachai). Maintainer invitations: pendientes manual (GitHub collaborators API endpoint returning 404 — probable API change).
