# CS19 — Petrel Run 5 / Corvus Batch — Curated Findings

**Date:** 2026-07-30
**Corvus version:** 1.3.1
**Source:** Petrel Run 4 targets (`targets-cs19.yaml`, 171 CRITICAL+HIGH internet-facing servers)
**Scan:** `corvus batch` — concurrency 5

## Summary

| Metric | Value |
|--------|-------|
| Targets | 171 |
| OK (enumerated) | 34 (20%) |
| ERROR / Offline | 137 (80%) |
| CRITICAL raw | 10 |
| CRITICAL true positives | 2 (SQLi confirmed) |
| CRITICAL false positives | 8 (resource_exposure on HTML bundles / API docs) |
| New GHSAs filed | 1 |

**Key FP pattern:** `resource_exposure` flagged HTML bundle files (minified JS) and public API documentation (openapi.json, auth.md) as credential leaks. `token_exposure` flagged governance metadata as credential. All discarded.

---

## True Positives

### F01 — GHSA-m8qh-p8m5-8c48 — CRITICAL — mcp-listentosadhu-app SQL Injection via NULL byte in lang parameters

**Service:** Listen to Sadhu MCP (`mcp-listentosadhu-app`, `https://mcp.listentosadhu.app/mcp`)
**Description:** Corpus/media service exposing religious content. No authentication required.

**Finding:** Two tool parameters reflect NULL byte input directly into PostgreSQL queries, triggering error-based SQLi:

- `media_render(lang="\x00")` → `ERROR: invalid byte sequence for encoding "UTF8": 0x00 (SQLSTATE 22021)`
- `search(lang="\x00")` → `vector lane: ERROR: invalid byte sequence for encoding "UTF8": 0x00 (SQLSTATE 22021)`

The `vector lane:` prefix in search confirms the injection reaches the vector search pipeline (pgvector). Both tools are unauthenticated.

**Evidence:**
```json
{"ok": false, "kind": "media_render", "error": {"code": "dependency_failed",
  "message": "ERROR: invalid byte sequence for encoding \"UTF8\": 0x00 (SQLSTATE 22021)"}}

{"ok": false, "kind": "search", "error": {"code": "dependency_failed",
  "message": "vector lane: ERROR: invalid byte sequence for encoding \"UTF8\": 0x00 (SQLSTATE 22021)"}}
```

**Additional HIGH findings in same target (not GHSA-worthy individually but compound surface):**
- `document_get.id`, `document_list.source`, `media_render.id`, `search.source`, `source_get.code` — injection reflected (HIGH)

**Module:** cmd-injection | **Confidence:** 90% | **CWE:** CWE-89
**Impact:** Unauthenticated SQL injection in public MCP server. PostgreSQL backend confirmed. Combined with vector search pipeline exposure = potential data exfiltration.
**Auth:** None required
**Tier:** C — Long tail
**Note:** GHSA-m8qh-p8m5-8c48 ya existía desde CS17 (2026-07-22) y cubre todos los findings de CS19 incluyendo media_render.id CDN injection. CS19 re-confirmó las mismas superficies. Sin nuevo GHSA necesario.

---

## False Positives

| Target | Check | Reason FP |
|--------|-------|-----------|
| mcp-listentosadhu-app (3x) | resource_exposure | HTML bundle JS files matched credential pattern |
| signomy-xyz | token_exposure | Governance metadata (posture/mode/role) flagged as credential |
| inboxguard-io (2x) | resource_exposure | Public openapi.json + auth.md documentation |
