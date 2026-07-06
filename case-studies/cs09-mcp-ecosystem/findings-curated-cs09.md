# CS09 — Smithery Ecosystem Findings (Curated)

**Date:** 2026-07-05  
**Corvus version:** 1.2.0  
**Targets scanned:** 30 (29 HTTP Smithery + 1 stdio)  
**Successful scans:** 1 (arxiv-smithery)  
**Errors:** 29 (HTTP 404 — require Smithery API key)  
**Raw findings:** 13  
**Curated TPs:** 9  
**FPs:** 4  
**TP rate:** ~69%

---

## Key Discovery: Smithery HTTP Auth Model

Most Smithery cloud-hosted servers require a Smithery API key (Bearer token) even when
`security: null` in the registry API. The `/mcp` path returns 404; auth gates are at
the root URL (`/`). Only servers officially designated as public (like arxiv) expose
`/mcp` without auth. **Updated `discover.py`** to add a connectivity probe before
including HTTP candidates — this ensures future discovery runs only include scannable
servers.

```
Servers attempted: 30
  arxiv-smithery:    200 OK → 13 findings
  29 others:         404 Not Found (require Smithery API key)
```

---

## Target: arxiv (arXiv MCP — Smithery Official)

**URL:** `https://arxiv.run.tools/mcp`  
**Transport:** HTTP  
**Server:** arXiv v1.0.0 (Smithery-hosted)  
**Tools:** `search_papers`, `get_paper`  
**Score:** 36/100

### Curated Findings

| ID | Severity | Module | Finding | TP/FP |
|----|----------|--------|---------|-------|
| CS09-F01 | HIGH | response-flood | `search_papers` returns 12,479 bytes — exceeds 8,192 threshold; unbounded pagination can DoS agent pipelines | TP |
| CS09-F02 | MEDIUM | schema-bypass | `search_papers` accepts empty args despite `required: ['query']` | TP |
| CS09-F03 | MEDIUM | init-audit | Protocol version downgrade — accepts all versions incl. `9999-99-99`, `""`, `0.1` | TP |
| CS09-F04 | MEDIUM | proto-fuzz | Missing `protocolVersion` crashes server (should return -32602) | TP |
| CS09-F05 | MEDIUM | proto-fuzz | Null request ID accepted (JSON-RPC 2.0 violation — null reserved for notifications) | TP |
| CS09-F06 | MEDIUM | proto-fuzz | Array request ID accepted (JSON-RPC 2.0 requires string/number/null) | TP |
| CS09-F07 | LOW | schema-bypass | `search_papers.query` silently accepts wrong type (None) | TP |
| CS09-F08 | LOW | init-audit | `protocolVersion` accepts integer (42) instead of string | TP |
| CS09-F09 | LOW | proto-fuzz | Missing `jsonrpc` field accepted (should return -32600) | TP |

### False Positives (4)

| Raw | Reason |
|-----|--------|
| CORVUS-001 INFO — Cloudflare server header | Infrastructure, not actionable |
| CORVUS-004 LOW — `__proto__` extra fields | Extra fields are allowed by JSON spec; not a security issue |
| CORVUS-009 INFO — completable arguments | Informational, no security risk |
| CORVUS-010 MEDIUM — path traversal cursor | cursor value in tools/list is opaque pagination token, not a file path; no actual traversal |

---

## Pattern: JSON-RPC Protocol Conformance Gap

The arxiv server shows a cluster of **protocol conformance failures** typical of
"MCP-over-HTTP" implementations that don't strictly validate the JSON-RPC 2.0 envelope:

1. `id: null` accepted → notification semantics violated
2. `id: [1,2,3]` accepted → type check missing
3. missing `jsonrpc` field → protocol version check missing
4. `protocolVersion: 42` accepted → no type coercion check
5. No version range validation → future/past versions all accepted

These are **low individual severity** but indicate the implementation prioritizes
convenience over correctness. In agent pipelines, malformed IDs can cause response
routing bugs.

---

## Pattern: Response Flooding in Search Tools

`search_papers` returns the full result set for broad queries (225,018 papers for "math").
**12,479 bytes** in a single tool call can:
- Overflow LLM context windows
- Push out system prompts via context stuffing
- DoS constrained agent pipelines

This is the same class of issue as CS08's response-flood cluster. A pagination cap (10
results max, not unlimited) would fix this.

---

## GHSAs

No GHSAs filed. All findings are in a hosted service (not a published package),
so there's no codebase to patch via GitHub Advisory. Protocol conformance issues
are informational at this severity level.

---

## Summary vs Prior Case Studies

| Study | Targets | OK | TP | Notes |
|-------|---------|----|----|-------|
| CS09 | 30 | 1 | 9 | Smithery HTTP — most need API key |
| CS08 | 177 | 51 | ~280 | Mixed npm+PyPI |
| CS07 | 11 | 1 | 9 | GitHub topics |
| CS06 | 26 | 12 | ~56 | npm+PyPI |

**Key insight:** Smithery's 97% cloud-hosted servers are not directly scannable without
their API key. Public servers (like arxiv) are rare. Future scans should either:
1. Use a Smithery API key to test the full 6,756-server catalog, or
2. Focus on the ~3% stdio servers discoverable via GitHub slug resolution.
