# Corvus Security Scan Report

**Target:** `uvx mcp-filesystem`
**Transport:** stdio
**Date:** 2026-07-05 20:26:12
**Duration:** 28.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | FileSystem |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 20 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 6 |
| MEDIUM | 4 |
| LOW | 8 |
| INFO | 1 |


**Total:** 19 finding(s)

---

## Findings



### CORVUS-001 — Parameter 'filter_type' in 'list_directory' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `list_directory` |
| Parameter | `filter_type` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'filter_type'.

---

### CORVUS-002 — Parameter 'content' in 'create_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `create_file` |
| Parameter | `content` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'content'.

---

### CORVUS-003 — Parameter 'start_line' in 'read_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `read_file` |
| Parameter | `start_line` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'start_line'.

---

### CORVUS-004 — Parameter 'end_line' in 'read_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `read_file` |
| Parameter | `end_line` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'end_line'.

---

### CORVUS-005 — Parameter 'line_number' in 'write_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `write_file` |
| Parameter | `line_number` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'line_number'.

---

### CORVUS-006 — Shadow Tool — 'create_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `create_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'create_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-007 — Shadow Tool — 'delete_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `delete_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'delete_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-008 — Shadow Tool — 'read_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `read_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'read_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-009 — Shadow Tool — 'write_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `write_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'write_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-010 — Token Exposure — internal IP address in 'get_system_info'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP01 |
| Tool | `get_system_info` |
| Parameter | `—` |
| Confidence | 70% |

Tool response contains internal IP address.



**Evidence:**
```
============================================================
SYSTEM INFORMATION
============================================================
Timestamp: 2026-07-05T20:26:08.696012
Python Version: 3.13.12 (main, Mar 24 2026, 22:56:40) [MSC v.1944 64 bit (AMD64)]
Python Implementation: CPython
Operating System: Windows 11
Architecture: AMD64
Platform: Windows-11-10.0.26200-SP0
Hostname: DESKTOP-TFV5V
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-011 — initialize accepts protocol version downgrade

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

### CORVUS-012 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

19 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-013 — Server accepts path traversal cursor without validation

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

### CORVUS-014 — Protocol crash — JSON-RPC batch array caused server disconnect

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
Server disconnected after batch. Pre-crash response: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-015 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-016 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-017 — Protocol crash — string params caused server disconnect

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

### CORVUS-018 — Server accepts requests without jsonrpc field

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

### CORVUS-019 — Server accepts array request ID — JSON-RPC spec violation

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



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*