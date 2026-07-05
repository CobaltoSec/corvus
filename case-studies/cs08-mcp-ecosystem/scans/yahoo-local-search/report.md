# Corvus Security Scan Report

**Target:** `uvx yahoo-local-search-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:34:18
**Duration:** 64.0s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mcp-yahoo-localsearch |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 3 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 31 |
| INFO | 1 |


**Total:** 39 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'search_local' inputSchema requests PII fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP02 |
| Tool | `search_local` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'search_local' inputSchema declares field(s) associated with PII: creditcard. Collecting PII through MCP tools may violate data minimization principles and privacy regulations.



**Evidence:**
```
inputSchema properties: creditcard
```


**Remediation:** Review whether collecting this PII is strictly necessary. Apply data minimization and ensure appropriate consent and handling.

---

### CORVUS-002 — Excessive description length in 'search_local'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `search_local` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1902 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-003 — High entropy description in 'search_local'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_local` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-004 — High entropy description in 'search_by_genre'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_by_genre` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-005 — High entropy description in 'search_nearby'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_nearby` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-006 — Parameter 'query' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `query` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'query'.

---

### CORVUS-007 — Parameter 'gc' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `gc` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'gc'.

---

### CORVUS-008 — Parameter 'ac' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `ac` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ac'.

---

### CORVUS-009 — Parameter 'lat' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `lat` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'lat'.

---

### CORVUS-010 — Parameter 'lon' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `lon` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'lon'.

---

### CORVUS-011 — Parameter 'dist' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `dist` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'dist'.

---

### CORVUS-012 — Parameter 'bbox' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `bbox` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'bbox'.

---

### CORVUS-013 — Parameter 'cid' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `cid` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'cid'.

---

### CORVUS-014 — Parameter 'open_param' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `open_param` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'open_param'.

---

### CORVUS-015 — Parameter 'coupon' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `coupon` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'coupon'.

---

### CORVUS-016 — Parameter 'parking' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `parking` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'parking'.

---

### CORVUS-017 — Parameter 'creditcard' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `creditcard` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'creditcard'.

---

### CORVUS-018 — Parameter 'smoking' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `smoking` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'smoking'.

---

### CORVUS-019 — Parameter 'reservation' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `reservation` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'reservation'.

---

### CORVUS-020 — Parameter 'image' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `image` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'image'.

---

### CORVUS-021 — Parameter 'maxprice' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `maxprice` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'maxprice'.

---

### CORVUS-022 — Parameter 'minprice' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `minprice` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'minprice'.

---

### CORVUS-023 — Parameter 'group' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `group` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'group'.

---

### CORVUS-024 — Parameter 'distinct' in 'search_local' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_local` |
| Parameter | `distinct` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'distinct'.

---

### CORVUS-025 — Parameter 'ac' in 'search_by_genre' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_by_genre` |
| Parameter | `ac` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ac'.

---

### CORVUS-026 — Parameter 'query' in 'search_by_genre' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_by_genre` |
| Parameter | `query` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'query'.

---

### CORVUS-027 — Parameter 'lat' in 'search_by_genre' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_by_genre` |
| Parameter | `lat` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'lat'.

---

### CORVUS-028 — Parameter 'lon' in 'search_by_genre' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_by_genre` |
| Parameter | `lon` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'lon'.

---

### CORVUS-029 — Parameter 'dist' in 'search_by_genre' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_by_genre` |
| Parameter | `dist` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'dist'.

---

### CORVUS-030 — Parameter 'query' in 'search_nearby' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_nearby` |
| Parameter | `query` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'query'.

---

### CORVUS-031 — Parameter 'gc' in 'search_nearby' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_nearby` |
| Parameter | `gc` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'gc'.

---

### CORVUS-032 — initialize accepts protocol version downgrade

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

### CORVUS-033 — initialize accepts type-confused protocolVersion (integer instead of string)

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

### CORVUS-034 — MCP server exposes tools with completable arguments

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

### CORVUS-035 — Server accepts path traversal cursor without validation

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

### CORVUS-036 — Protocol crash — JSON-RPC batch array caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 85% |

Sending a JSON-RPC 2.0 batch (5 requests as an array) caused the server to crash or disconnect. MCP does not define batch semantics; servers must reject arrays gracefully.


**Payload:**
```
[{"jsonrpc":"2.0","id":9000,"method":"tools/list"}, … (5 items)]
```


**Evidence:**
```
Server disconnected after batch. Pre-crash response: none
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-037 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-038 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-039 — Protocol crash — string params caused server disconnect

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