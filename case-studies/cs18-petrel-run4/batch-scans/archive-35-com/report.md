# Corvus Security Scan Report

**Target:** `https://archive-35.com/mcp`
**Transport:** http
**Date:** 2026-07-28 17:03:27
**Duration:** 12.0s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | archive-35-mcp-server |
| Version | 1.0.0 |
| Protocol | 2025-11-25 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 4 |
| Resources | 3 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 9 |
| LOW | 6 |
| INFO | 2 |


**Total:** 19 finding(s)

---

## Findings



### CORVUS-001 — Injection reflected — 'archive35_search_products.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `archive35_search_products` |
| Parameter | `query` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
{
  "total_matches": 0,
  "showing": 0,
  "query": "' OR '1'='1",
  "results": []
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-002 — Injection reflected — 'archive35_get_product.id'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `archive35_get_product` |
| Parameter | `id` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{
  "error": "Product \"<script>alert(1)</script>\" not found. Valid IDs: a-001 to a-044, gt-001 to gt-048, nz-001 to nz-016, sa-001 to sa-006."
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-003 — Injection reflected — 'archive35_get_collection.collection'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `archive35_get_collection` |
| Parameter | `collection` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{
  "error": "Collection \"<script>alert(1)</script>\" not found. Valid: africa, grand-teton, new-zealand, south-africa."
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-004 — Token Exposure — server version disclosure in HTTP response headers

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | MCP01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

HTTP response header 'server: cloudflare' discloses internal information.



**Evidence:**
```
server: cloudflare
```


**Remediation:** Remove the 'server' response header in production.

---

### CORVUS-005 — 'archive35_search_products' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `archive35_search_products` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['query']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-006 — 'archive35_search_products.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `archive35_search_products` |
| Parameter | `query` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-007 — 'archive35_get_product' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `archive35_get_product` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['id']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-008 — 'archive35_get_product.id' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `archive35_get_product` |
| Parameter | `id` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-009 — 'archive35_get_collection' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `archive35_get_collection` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['collection']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-010 — 'archive35_get_collection.collection' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `archive35_get_collection` |
| Parameter | `collection` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-011 — Response Flooding — 'archive35_get_catalog_summary' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `archive35_get_catalog_summary` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'archive35_get_catalog_summary' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
{
  "store": {
    "name": "Archive-35",
    "tagline": "Light. Place. Time.",
    "description": "Fine art landscape and wildlife photography prints by Wolf. 17+ years, 55+ countries.",
    "url": "https://archive-35.com",
    "artist": "Wolf",
    "copyright": "© 2026 Wolf / Archive-35. All rights
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-012 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""', '0.1']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""', '0.1']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

---

### CORVUS-013 — initialize crash — missing protocolVersion causes unhandled error

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

Sending initialize without the required protocolVersion field caused the server to crash or return an unexpected result. Servers must validate required fields and return -32602 (Invalid params).



**Evidence:**
```
initialize({capabilities:{}, clientInfo:{...}}) — no protocolVersion
```


**Remediation:** Add required-field validation to the initialize handler.

---

### CORVUS-014 — initialize accepts type-confused protocolVersion (integer instead of string)

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

The server accepted an initialize request where protocolVersion was an integer (42) instead of a string. Strict type checking prevents parser confusion and unexpected coercion behavior.



**Evidence:**
```
protocolVersion: 42 (integer) → server returned serverInfo
```


**Remediation:** Validate that protocolVersion is a string before processing.

---

### CORVUS-015 — Null request ID accepted — JSON-RPC spec violation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 60% |

The server accepted a request with id=null and returned a result. Per JSON-RPC 2.0, null IDs are reserved for notifications (no response expected). Accepting them may cause response routing bugs in complex orchestration scenarios.




**Remediation:** Reject requests with null id values; treat them as notifications.

---

### CORVUS-016 — Server accepts requests without jsonrpc field

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

The server returned a successful result to a request missing the required 'jsonrpc' field. Per JSON-RPC 2.0, this field is mandatory and must equal '2.0'.


**Payload:**
```
{"id": 9600, "method": "tools/list", "params": {}}
```



**Remediation:** Validate that the 'jsonrpc' field is present and equals '2.0' before processing. Return -32600 (Invalid Request) for non-conformant messages.

---

### CORVUS-017 — Server accepts array request ID — JSON-RPC spec violation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

The server returned a successful result to a request with an array as the request ID. JSON-RPC 2.0 requires the id to be a string, number, or null.


**Payload:**
```
{"jsonrpc": "2.0", "id": [1, 2, 3], "method": "tools/list"}
```



**Remediation:** Validate that the request 'id' is a string, number, or null. Return -32600 (Invalid Request) for array or object IDs.

---

### CORVUS-018 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

3 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-019 — Server accepts path traversal cursor without validation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT13 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

tools/list accepted cursor='../../../../etc/passwd' and returned a result instead of rejecting it. This may indicate missing cursor validation.


**Payload:**
```
../../../../etc/passwd
```



**Remediation:** Validate cursor values; reject non-opaque or path-like cursor strings.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*