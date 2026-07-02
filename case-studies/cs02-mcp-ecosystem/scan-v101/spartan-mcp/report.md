# Corvus Security Scan Report

**Target:** `npx -y @spartan-ng/mcp`
**Transport:** stdio
**Date:** 2026-07-02 14:53:14
**Duration:** 99.1s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | spartan-ui |
| Version | 0.0.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 17 |
| Resources | 172 |
| Prompts | 5 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 2 |
| INFO | 3 |


**Total:** 9 finding(s)

---

## Findings



### CORVUS-001 — 'spartan_health_check' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `spartan_health_check` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-002 — 'spartan_cache_clear' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `spartan_cache_clear` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-003 — 'spartan_cache_rebuild' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `spartan_cache_rebuild` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-004 — Resource URI — large attack surface (172 resources exposed)

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT05 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 60% |

The server exposes 172 MCP resources (threshold: 20). A large resource surface increases the risk of accidentally exposing sensitive data and makes it harder for operators to audit what information is accessible.



**Evidence:**
```
172 resources
```


**Remediation:** Audit each exposed resource for necessity. Apply the principle of least exposure — only surface resources that callers explicitly need.

---

### CORVUS-005 — Injection reflected — 'spartan_components_get.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `spartan_components_get` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
null
```


**Evidence:**
```
{
  "url": "https://www.spartan.ng/components/null",
  "extract": "code",
  "count": 0,
  "data": [],
  "cacheInfo": "[NEWLY CACHED - Version: latest]",
  "version": "latest",
  "processingInstructions": "Always parse and present the API information, code examples, and component specifications from 
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-006 — Injection reflected — 'spartan_components_get.spartanVersion'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `spartan_components_get` |
| Parameter | `spartanVersion` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
null
```


**Evidence:**
```
{
  "url": "https://www.spartan.ng/components/test",
  "extract": "code",
  "count": 0,
  "data": [],
  "cacheInfo": "[CACHE REFRESHED - Version: null]",
  "version": "null",
  "processingInstructions": "Always parse and present the API information, code examples, and component specifications from t
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