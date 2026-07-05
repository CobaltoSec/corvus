# Corvus Security Scan Report

**Target:** `uvx arxiv-today-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:17:49
**Duration:** 71.3s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | arxiv |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 5 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 4 |
| LOW | 11 |
| INFO | 2 |


**Total:** 22 finding(s)

---

## Findings



### CORVUS-001 — Excessive description length in 'query_papers'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `query_papers` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1018 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-002 — Parameter 'date' in 'fetch_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `fetch_papers` |
| Parameter | `date` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'date'.

---

### CORVUS-003 — Parameter 'date' in 'query_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query_papers` |
| Parameter | `date` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'date'.

---

### CORVUS-004 — Parameter 'categories' in 'query_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query_papers` |
| Parameter | `categories` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'categories'.

---

### CORVUS-005 — Parameter 'title' in 'query_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query_papers` |
| Parameter | `title` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'title'.

---

### CORVUS-006 — Parameter 'entry_ids' in 'query_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query_papers` |
| Parameter | `entry_ids` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'entry_ids'.

---

### CORVUS-007 — Parameter 'fields' in 'query_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query_papers` |
| Parameter | `fields` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'fields'.

---

### CORVUS-008 — Parameter 'before_date' in 'cleanup_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `cleanup_papers` |
| Parameter | `before_date` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'before_date'.

---

### CORVUS-009 — Parameter 'date' in 'cleanup_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `cleanup_papers` |
| Parameter | `date` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'date'.

---

### CORVUS-010 — Parameter 'categories' in 'cleanup_papers' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `cleanup_papers` |
| Parameter | `categories` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'categories'.

---

### CORVUS-011 — 'cleanup_papers' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `cleanup_papers` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-012 — Injection reflected — 'fetch_papers.category'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `fetch_papers` |
| Parameter | `category` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{
  "status": "ok",
  "category": "<script>alert(1)</script>",
  "papers_fetched": 0,
  "num_days": 3
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-013 — Slow tool response — 'query_papers' took 19.8s

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `query_papers` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'query_papers' took 19.8 seconds to respond. Slow responses can be used for resource exhaustion in agent pipelines or indicate unbounded computation triggered by benign inputs.



**Evidence:**
```
Response time: 19.84s
```


**Remediation:** Enforce server-side timeouts on all tool executions. Cap at 30s max.

---

### CORVUS-014 — SSRF (timeout) — 'fetch_papers.category' hung on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `fetch_papers` |
| Parameter | `category` |
| Confidence | 65% |

Call with SSRF payload 'http://169.254.169.254/' timed out after 12.0s, suggesting the server is attempting the network request.


**Payload:**
```
http://169.254.169.254/
```



**Remediation:** Block outbound requests to RFC-1918 and link-local ranges. Use an allowlist for permitted URL schemes and hosts.

---

### CORVUS-015 — SSRF (timing) — 'fetch_papers.date' delayed on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `fetch_papers` |
| Parameter | `date` |
| Confidence | 70% |

Call with payload 'http://169.254.169.254/latest/meta-data/' took 7.8s vs baseline 2.0s — server likely attempted the outbound request before timing out.


**Payload:**
```
http://169.254.169.254/latest/meta-data/
```



**Remediation:** Block outbound requests to RFC-1918 and link-local ranges. Use an allowlist for permitted URL schemes and hosts.

---

### CORVUS-016 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

---

### CORVUS-017 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

4 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-018 — Server hangs on path traversal cursor

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT13 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 80% |

The server crashed or disconnected when processing an invalid cursor value. This is a Denial of Service vector.



**Evidence:**
```
tools/list timed out with cursor='../../../../etc/passwd'
```


**Remediation:** Validate cursor values before processing; return -32602 (Invalid params) for malformed cursors.

---

### CORVUS-019 — Protocol crash — JSON-RPC batch array caused server disconnect

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

### CORVUS-020 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-021 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-022 — Protocol crash — string params caused server disconnect

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