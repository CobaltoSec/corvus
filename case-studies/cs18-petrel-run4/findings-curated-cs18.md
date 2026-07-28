# CS18 — Petrel Run 4 — Curated Findings

**Date:** 2026-07-28
**Corvus version:** 1.3.1
**Source:** Petrel Run 4 targets (`targets-v08.yaml`, 39 CRITICAL+HIGH internet-facing servers)
**Scan:** `corvus batch --verify-critical` — concurrency 5, --timeout 30, --target-timeout 120

## Summary

| Metric | Value |
|--------|-------|
| Targets | 39 (CRITICAL+HIGH from Petrel Run 4) |
| OK (enumerated) | 17 (44%) |
| ERROR / Offline | 22 (56%) |
| Raw findings | ~225 |
| CRITICAL raw | 12 (all re-confirmed by --verify-critical) |
| CRITICAL true positives | 4 (rest: 8 FP — resource_exposure on docs/educational content) |
| HIGH true positives | ~15 |
| New GHSAs filed | 4 |

**Key FP pattern:** `resource_exposure` module detected 8 false-positive CRITICALs on frootai-dev (7) and dayze-com (1) — MCP resources serving educational/API documentation text were flagged as credential leaks. See FP section below.

---

## True Positives

### F01 — GHSA-54hx-rhpf-r7r7 — HIGH — glimind-oracle Bearer Token Exposed in watch_tool Response

**Service:** Glimind Oracle MCP (`glimind-oracle` v0.1.0, `https://glimind.com/mcp`)
**Description:** Tool routing / reliability oracle. Companion advisory to GHSA-7rqv (SSRF).

**Finding:** `watch_tool` returns a live subscription bearer token in unauthenticated responses:

```json
{"subscriptionId": "128", "token": "iAKOJTgB76YoJ6HhpnvNyEmhON_Bb9EN", "channel": "pull", ...}
```

Any MCP client calling `watch_tool` harvests a valid token without authentication.

**Module:** token-exposure | **Confidence:** 85% | **CWE:** CWE-200, CWE-522
**Impact:** Subscription channel unauthorized access + replay attacks. Combined with SSRF in GHSA-7rqv = compound attack surface.

---

### F02 — GHSA-w5ph-rcqg-79hm — HIGH — dayze-mcp Prompt Template Injection via prompts/get

**Service:** Dayze MCP (`dayze-mcp`, `https://dayze.com/api/mcp`)
**Description:** Notable person data and life timeline service.

**Finding:** Three `prompts/get` endpoints reflect injection payloads verbatim in `messages[]`:

| Prompt | Parameter | Confidence |
|--------|-----------|------------|
| `notable_pack` | `slug` | 88% |
| `compare_lives` | `slug_a`, `slug_b` | 88% |
| `birthday_peers` | `slug` | 88% |

Payload `CORVUS_INJECTION_TEST` was confirmed in `messages[].content.text`.

**Module:** prompts-injection | **CWE:** CWE-74, CWE-116
**Impact:** LLM context hijacking for any AI client consuming these prompt templates. Enables unauthorized tool calls, data exfiltration, session manipulation.

**Note:** CRITICAL finding (resource_exposure on `dayze://docs/agents`) is FP — API integration guide, not a credential.

---

### F03 — GHSA-h4xr-39qc-6j9x — HIGH — nexus-agent-mcp Injection, Flooding, and Suspected SSRF

**Service:** Nexus Agent MCP (`nexus-agent-mcp`, `https://nexus-agent-xa12.onrender.com`)
**Description:** AI agent with ACI directory integration and competitive intelligence tools.

**Findings:**

1. **Injection (conf=85):** `talk_to_nexus.message` and `aci_find.type` reflect payloads verbatim
2. **Response Flooding (conf=85):** `aci_directory` returns 10,605 bytes (threshold 8,192)
3. **Suspected SSRF (conf=65, unconfirmed):** `generate_llms_txt.url`, `check_ai_visibility_score.url`, `scan_competitor_ai_presence.url` hang 8s+ on IMDS payloads — no metadata in response

**Module:** injection, response-flood, ssrf | **CWE:** CWE-74, CWE-400, CWE-918
**Impact:** Injection enables LLM context hijacking. Flooding risks context overflow. SSRF suspected but unconfirmed.

---

### F04 — GHSA-p3xc-rmwr-74rv — HIGH — ucpchecker-mcp Dual Injection

**Service:** UCP Checker MCP (`ucpchecker-mcp`, `https://ucpchecker.com`)
**Description:** Store listing and product shopping assistant.

**Findings:**

1. **Tool injection (conf=85):** `list-stores.category` reflects generic string payload verbatim
2. **Prompt injection (conf=88):** `shop-for-product` (prompts/get) reflects payload in messages array

**Module:** injection, prompts-injection | **CWE:** CWE-74, CWE-116
**Impact:** Dual injection surface — covers both tool-call and prompt-template attack vectors.

---

## Minor TPs (HIGH) — Queue for Next Session

| Target | Finding | Conf | GHSA? |
|--------|---------|------|-------|
| gitdealflow.com | Injection reflected — `get_startup_signal.startup` | 85 | Queue |
| scoreboard.urdr.dev | Scope Creep — `get_match` unrestricted access | 85 | Queue |
| archive-35.com | Injection ×2 (`archive35_get_product.id`, `archive35_get_collection`) | 85 | Queue |
| www.vivaldo.shop | Log level escalation to DEBUG (unauthenticated) | 85 | Queue |
| vaaya.ai | Shadow Tool ×2 (`consult`, `use`) — exec keywords | 80 | Review manually |

---

## False Positives — resource_exposure FP Pattern

**8/12 CRITICALs are FALSE POSITIVES** — `resource_exposure` module detecting documentation/educational content as credential leaks:

| Target | Resources flagged | Actual content |
|--------|------------------|----------------|
| `frootai-dev` | 7 (O1/O2/O3/R1/R2/T2/V1) | Training modules (Semantic Kernel, AI Agents, MCP, RAG, etc.) |
| `dayze-com` | 1 (`dayze://docs/agents`) | API integration guide (endpoints + methods) |

**Root cause:** `resource_exposure` has no guard against educational/documentation text. Content matching patterns like `POST https://`, `## Duration:`, module headings with auth-adjacent keywords triggers the detector.

**Recommended fix:** Add `_is_documentation_content()` guard — signals: markdown `## Duration:`, `## Audience:`, `### Module`, `POST https://` or `GET https://` at start of lines in a documentation-style document, or `resource_exposure` content without actual key=value or token patterns.

**Impact on --verify-critical:** The re-confirmation pass confirms the tool returns the same content — it does NOT evaluate whether the content is actually a secret. All 8 FP CRITICALs were "re-confirmed" because the educational content is stable. This is an expected limitation of the verification approach.

---

## Disclosure Timeline

| GHSA | Target | Severity | Filed | Deadline |
|------|--------|----------|-------|---------|
| GHSA-54hx-rhpf-r7r7 | glimind-oracle (token) | HIGH | 2026-07-28 | 2026-10-26 |
| GHSA-w5ph-rcqg-79hm | dayze-mcp | HIGH | 2026-07-28 | 2026-10-26 |
| GHSA-h4xr-39qc-6j9x | nexus-agent-mcp | HIGH | 2026-07-28 | 2026-10-26 |
| GHSA-p3xc-rmwr-74rv | ucpchecker-mcp | HIGH | 2026-07-28 | 2026-10-26 |
