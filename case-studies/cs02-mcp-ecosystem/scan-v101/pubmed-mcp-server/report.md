# Corvus Security Scan Report

**Target:** `npx -y @cyanheads/pubmed-mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 14:49:44
**Duration:** 102.2s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | @cyanheads/mcp-ts-core |
| Version | 0.8.18 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 9 |
| Resources | 1 |
| Prompts | 1 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 1 |
| LOW | 3 |
| INFO | 1 |


**Total:** 9 finding(s)

---

## Findings



### CORVUS-001 — 'pubmed_fetch_fulltext' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `pubmed_fetch_fulltext` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-002 — Parameter 'format' in 'pubmed_format_citations' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `pubmed_format_citations` |
| Parameter | `format` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'format'.

---

### CORVUS-003 — Injection reflected — 'pubmed_search_articles.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `pubmed_search_articles` |
| Parameter | `query` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
## PubMed Search Results
**Query:** ' OR '1'='1
**Effective Query:** ' OR '1'='1
**Total Found:** 185783 | **Returned:** 20 | **Offset:** 0
**Search URL:** https://pubmed.ncbi.nlm.nih.gov/?term='%20OR%20'1'%3D'1

**PMIDs:** 30000545, 30000564, 30000563, 30000559, 29999787, 30000679, 30000059, 300006
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-004 — Injection reflected — 'pubmed_search_articles.author'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `pubmed_search_articles` |
| Parameter | `author` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
## PubMed Search Results
**Query:** test
**Effective Query:** test AND ' OR '1'='1[Author]
**Total Found:** 0 | **Returned:** 0 | **Offset:** 0
**Search URL:** https://pubmed.ncbi.nlm.nih.gov/?term=test%20AND%20'%20OR%20'1'%3D'1%5BAuthor%5D

### Applied Filters
- **Author:** ' OR '1'='1

> No result
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-005 — Injection reflected — 'pubmed_search_articles.journal'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `pubmed_search_articles` |
| Parameter | `journal` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
## PubMed Search Results
**Query:** test
**Effective Query:** test AND "' OR '1'='1"[Journal]
**Total Found:** 0 | **Returned:** 0 | **Offset:** 0
**Search URL:** https://pubmed.ncbi.nlm.nih.gov/?term=test%20AND%20%22'%20OR%20'1'%3D'1%22%5BJournal%5D

### Applied Filters
- **Journal:** ' OR '1'='1


```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-006 — Injection reflected — 'pubmed_search_articles.language'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `pubmed_search_articles` |
| Parameter | `language` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
## PubMed Search Results
**Query:** test
**Effective Query:** test AND ' OR '1'='1[Language]
**Total Found:** 0 | **Returned:** 0 | **Offset:** 0
**Search URL:** https://pubmed.ncbi.nlm.nih.gov/?term=test%20AND%20'%20OR%20'1'%3D'1%5BLanguage%5D

### Applied Filters
- **Language:** ' OR '1'='1

> No 
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-007 — Protocol crash — oversized method name caused transport failure

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 80% |

The server failed to respond to a request with an 8192-byte method name. A robust server should return a JSON-RPC error, not disconnect or crash.


**Payload:**
```
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...' (8192 bytes)
```



**Remediation:** Add input length validation at the JSON-RPC parsing layer. Return -32700 (parse error) or -32600 (invalid request) for malformed inputs.

---

### CORVUS-008 — Protocol crash — deeply nested params caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

Sending a tools/call request with 50-level nested params caused the server to disconnect or crash. Deep nesting can cause stack overflows or excessive memory use in recursive JSON parsers.


**Payload:**
```
tools/call {arguments: {x: {x: {x: ... (50 levels)}}}}
```



**Remediation:** Limit JSON object nesting depth at parse time (recommended: ≤32 levels). Return -32700 (Parse error) for inputs exceeding the depth limit.

---

### CORVUS-009 — Protocol crash — string params caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Sending a tools/call request where params is a string (not an object) caused the server to crash or disconnect. The JSON-RPC spec requires params to be an array or object.


**Payload:**
```
{"method":"tools/call","params":"not-an-object"}
```



**Remediation:** Validate params type (must be object or array) before processing. Return -32600 (Invalid Request) for wrong types.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*