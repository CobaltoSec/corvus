# Corvus Security Scan Report

**Target:** `uvx mcp-file-tool`
**Transport:** stdio
**Date:** 2026-07-05 20:26:19
**Duration:** 20.8s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | BigFile MCP Service |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 13 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 4 |
| LOW | 26 |
| INFO | 1 |


**Total:** 33 finding(s)

---

## Findings



### CORVUS-001 — High entropy description in 'read_bytes'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `read_bytes` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-002 — High entropy description in 'read_lines'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `read_lines` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-003 — High entropy description in 'read_last_lines'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `read_last_lines` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-004 — High entropy description in 'write_overwrite'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `write_overwrite` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-005 — High entropy description in 'insert'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `insert` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-006 — High entropy description in 'build_line_index'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `build_line_index` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-007 — High entropy description in 'search_regex'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_regex` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-008 — High entropy description in 'search_literal'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_literal` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-009 — High entropy description in 'build_inverted_index'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `build_inverted_index` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-010 — High entropy description in 'search_index_term'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_index_term` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-011 — High entropy description in 'line_number_at_offset'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `line_number_at_offset` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-012 — Parameter 'ctx' in 'read_bytes' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `read_bytes` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-013 — Parameter 'ctx' in 'read_lines' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `read_lines` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-014 — Parameter 'ctx' in 'read_last_lines' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `read_last_lines` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-015 — Parameter 'ctx' in 'write_overwrite' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `write_overwrite` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-016 — Parameter 'ctx' in 'append' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `append` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-017 — Parameter 'temp_dir' in 'insert' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `insert` |
| Parameter | `temp_dir` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'temp_dir'.

---

### CORVUS-018 — Parameter 'ctx' in 'insert' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `insert` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-019 — Parameter 'ctx' in 'file_info' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `file_info` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-020 — Parameter 'ctx' in 'build_line_index' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `build_line_index` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-021 — Parameter 'end_offset' in 'search_regex' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_regex` |
| Parameter | `end_offset` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'end_offset'.

---

### CORVUS-022 — Parameter 'flags' in 'search_regex' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_regex` |
| Parameter | `flags` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'flags'.

---

### CORVUS-023 — Parameter 'end_offset' in 'search_literal' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_literal` |
| Parameter | `end_offset` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'end_offset'.

---

### CORVUS-024 — Parameter 'ctx' in 'line_number_at_offset' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `line_number_at_offset` |
| Parameter | `ctx` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'ctx'.

---

### CORVUS-025 — initialize accepts protocol version downgrade

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

### CORVUS-026 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

13 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-027 — Server accepts path traversal cursor without validation

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

### CORVUS-028 — Protocol crash — JSON-RPC batch array caused server disconnect

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
Server disconnected after batch. Pre-crash response: {"jsonrpc":"2.0","id":48,"result":{"content":[{"type":"text","text":"Error executing tool append: No
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-029 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-030 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-031 — Protocol crash — string params caused server disconnect

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

### CORVUS-032 — Server accepts requests without jsonrpc field

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

### CORVUS-033 — Server accepts array request ID — JSON-RPC spec violation

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