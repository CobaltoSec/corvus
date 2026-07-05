# Corvus Security Scan Report

**Target:** `uvx mcp-gdocs`
**Transport:** stdio
**Date:** 2026-07-05 20:26:56
**Duration:** 57.0s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mcp-gdocs |
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
| HIGH | 1 |
| MEDIUM | 6 |
| LOW | 2 |
| INFO | 1 |


**Total:** 10 finding(s)

---

## Findings



### CORVUS-001 — Token Exposure — Windows user path in 'markdown_to_gdoc'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `markdown_to_gdoc` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains Windows user path.



**Evidence:**
```
Error executing tool markdown_to_gdoc: Google OAuth credentials not found at C:\Users\nicol\AppData\Local\uv\cache\archive-v0\pHCiuUmsbfQN6fOnMzhb8\Lib\credentials\client_secret.json. Download from Google Cloud Console → APIs & Services → Credentials.
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-002 — Token Exposure — Windows user path in 'update_google_doc'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `update_google_doc` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains Windows user path.



**Evidence:**
```
Error executing tool update_google_doc: Google OAuth credentials not found at C:\Users\nicol\AppData\Local\uv\cache\archive-v0\pHCiuUmsbfQN6fOnMzhb8\Lib\credentials\client_secret.json. Download from Google Cloud Console → APIs & Services → Credentials.
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-003 — Token Exposure — Windows user path in 'list_google_docs'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `list_google_docs` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains Windows user path.



**Evidence:**
```
Error executing tool list_google_docs: Google OAuth credentials not found at C:\Users\nicol\AppData\Local\uv\cache\archive-v0\pHCiuUmsbfQN6fOnMzhb8\Lib\credentials\client_secret.json. Download from Google Cloud Console → APIs & Services → Credentials.
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-004 — initialize accepts protocol version downgrade

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

### CORVUS-005 — initialize accepts type-confused protocolVersion (integer instead of string)

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

### CORVUS-006 — MCP server exposes tools with completable arguments

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

### CORVUS-007 — Server accepts path traversal cursor without validation

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

### CORVUS-008 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-009 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-010 — Protocol crash — string params caused server disconnect

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