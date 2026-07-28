# Corvus Security Scan Report

**Target:** `https://www.vivaldo.shop/mcp`
**Transport:** http
**Date:** 2026-07-28 16:57:32
**Duration:** 8.5s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | vivaldo-shop-mcp |
| Version | 1.1.1 |
| Protocol | 2025-03-26 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 4 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 6 |
| LOW | 5 |
| INFO | 2 |


**Total:** 14 finding(s)

---

## Findings



### CORVUS-001 — Injection reflected — 'search_products.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `search_products` |
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
  "query": "' OR '1'='1",
  "count": 0,
  "products": []
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-002 — Token Exposure — server version disclosure in HTTP response headers

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

### CORVUS-003 — 'search_products.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `search_products` |
| Parameter | `query` |
| Confidence | 80% |

Expected type 'string', sent int value '12345' — no error returned.


**Payload:**
```
12345
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-004 — 'get_collection_products.collection_handle' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_collection_products` |
| Parameter | `collection_handle` |
| Confidence | 80% |

Expected type 'string', sent int value '12345' — no error returned.


**Payload:**
```
12345
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-005 — initialize accepts protocol version downgrade

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

### CORVUS-006 — initialize crash — missing protocolVersion causes unhandled error

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

### CORVUS-007 — initialize accepts type-confused protocolVersion (integer instead of string)

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

### CORVUS-008 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-009 — Server accepts requests without jsonrpc field

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

### CORVUS-010 — Server accepts array request ID — JSON-RPC spec violation

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

### CORVUS-011 — MCP server exposes tools with completable arguments

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

### CORVUS-012 — Server allows external log level escalation to DEBUG

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT11 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 85% |

The MCP server accepted an unauthenticated logging/setLevel request with level='debug'. This may expose tokens, internal paths, and sensitive state in log streams accessible to the operator.



**Evidence:**
```
logging/setLevel with level='debug' and level='emergency' both returned success
```


**Remediation:** Restrict logging/setLevel to admin contexts or disable it entirely.

---

### CORVUS-013 — Server accepts arbitrary logging levels without validation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT11 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

logging/setLevel accepted the value 'INVALID_LEVEL_CORVUS', indicating the server does not validate log level values.



**Evidence:**
```
logging/setLevel with level='INVALID_LEVEL_CORVUS' returned success
```


**Remediation:** Validate logging level against the MCP-defined set (debug/info/warning/error/critical).

---

### CORVUS-014 — Server accepts path traversal cursor without validation

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